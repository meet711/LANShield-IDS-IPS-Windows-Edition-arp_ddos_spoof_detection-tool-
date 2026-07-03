#!/usr/bin/env python3
"""
main.py  –  LAN-Shield IDS/IPS Entry Point 
============================================================

REQUIREMENTS BEFORE RUNNING
────────────────────────────
1. Install Npcap (mandatory for Scapy packet capture on Windows):
     https://npcap.com/#download
     During install: CHECK "WinPcap API-compatible Mode"

2. Install Python dependencies:
     pip install scapy flask colorama firebase-admin

3. Run as Administrator:
     Right-click → "Run as administrator"  OR
     Open an elevated PowerShell and run:  python main.py

4. Kali attacker and this Windows host must be on the same LAN
   (Bridged adapter in VirtualBox/VMware).

HOW IT WORKS
────────────
  1. Auto-detect host IP, MAC, gateway, interface.
  2. ARP-scan the local subnet → build a verified ground-truth baseline
     BEFORE live sniffing starts (prevents baseline poisoning).
  3. Inject the baseline into ARPSpoofDetector via seed_baseline().
  4. Start sniffing.  Every ARP packet runs three independent checks:
       • MAC → multiple IPs  (primary attacker fingerprint)
       • IP  → MAC mismatch  (deviation from verified baseline)
       • Gateway impersonation (critical alert)
  5. Confirmed attacks → Windows Firewall block via netsh advfirewall.
  6. All events → terminal + attacks.log + Flask dashboard.
"""

import sys
import os
import atexit
import socket
import signal
import threading
import ctypes
import ipaddress

# ── Admin privilege check ─────────────────────────────────────────
def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ── Scapy import ──────────────────────────────────────────────────
try:
    from scapy.all import (
        conf, get_if_addr, get_if_hwaddr, sniff,
        ARP, IP, Ether, srp, IFACES,
    )
except ImportError:
    print("[ERROR] Scapy not installed.  Run:  pip install scapy")
    sys.exit(1)

from arp_detection import ARPSpoofDetector
from firewall      import FirewallManager
from logger        import Logger
from config        import Config


# ─────────────────────────────────────────────
#  Host / interface helpers
# ─────────────────────────────────────────────

def get_host_ip() -> str:
    """
    Detect the primary non-loopback IPv4 address without needing
    an actual internet connection (the UDP socket is never sent).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_best_interface(host_ip: str) -> str:
    """
    Find the Npcap interface whose IPv4 address matches host_ip.
    Falls back to Scapy's default interface.
    """
    for iface_name in IFACES:
        try:
            if get_if_addr(iface_name) == host_ip:
                return iface_name
        except Exception:
            continue
    return str(conf.iface)


def describe_interface(iface: str) -> str:
    """Human-readable name for a Windows/Npcap interface GUID."""
    try:
        obj = IFACES.get(iface)
        if obj:
            return getattr(obj, "description", iface)
    except Exception:
        pass
    return iface


def get_gateway_ip() -> str:
    """Return the default gateway IP from Scapy's routing table."""
    try:
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return "0.0.0.0"


def get_subnet_network(host_ip: str, prefix: int = 24) -> str:
    """
    Compute the correct /prefix network address for an IP.
    e.g. host_ip=192.168.1.55, prefix=24 → '192.168.1.0/24'

    We use strict=False so host bits are silently masked out.
    """
    net = ipaddress.IPv4Network(f"{host_ip}/{prefix}", strict=False)
    return str(net)


def print_interfaces():
    """Print a formatted table of all Npcap-visible interfaces at startup."""
    print("\n  Available network interfaces:")
    print(f"  {'#':<4} {'IP Address':<18} Description")
    print(f"  {'-'*4} {'-'*18} {'-'*42}")
    for idx, (name, obj) in enumerate(IFACES.items()):
        try:
            addr = get_if_addr(name)
            desc = getattr(obj, "description", name)
            print(f"  {idx:<4} {addr:<18} {desc}")
        except Exception:
            pass
    print()


# ─────────────────────────────────────────────
#  ARP baseline scan
# ─────────────────────────────────────────────

def build_arp_baseline(interface: str, host_ip: str) -> dict[str, str]:
    """
    Send broadcast ARP requests to the /24 subnet and collect replies.
    Returns a dict of {ip: mac} for all responding hosts.

    Why this matters
    ────────────────
    This scan runs BEFORE sniffing starts.  Its results become the
    verified ground-truth table.  Even if an attack is already running
    when we start, the scan captures the REAL MAC→IP state because:
      • We send the probe ourselves (not trusting ambient traffic)
      • We filter out null MACs (00:00:00:00:00:00)
      • The result is injected as the immutable baseline

    If the attacker replies to our probe, the multi-IP signal will
    immediately catch them (one MAC, two IPs) before sniffing begins.
    """
    subnet = get_subnet_network(host_ip, prefix=24)
    print(f"[*] ARP scan → {subnet}  (timeout 3 s) …")

    try:
        arp_req   = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(
            broadcast / arp_req,
            iface   = interface,
            timeout = 3,
            verbose = False,
        )
    except Exception as e:
        Logger.log_event("SYSTEM", "0.0.0.0", f"ARP scan failed: {e}")
        return {}

    baseline: dict[str, str] = {}
    null_mac  = "00:00:00:00:00:00"

    for sent, received in answered:
        ip  = received[ARP].psrc.strip()
        mac = received[ARP].hwsrc.strip().lower()

        if not ip or mac == null_mac or ip == host_ip:
            continue

        if ip in baseline and baseline[ip] != mac:
            # Two different MACs replied for the same IP during the scan —
            # that itself is a spoof signal.  Log it; keep the first reply.
            Logger.log_event(
                "ARP_SPOOF",
                ip,
                f"[SCAN CONFLICT] IP {ip} answered with BOTH "
                f"{baseline[ip]} AND {mac} — possible active spoof during scan"
            )
            continue

        baseline[ip] = mac

    print(f"[*] ARP scan complete — {len(baseline)} hosts found.")
    for ip, mac in list(baseline.items())[:10]:
        print(f"    {ip:<18} → {mac}")
    if len(baseline) > 10:
        print(f"    … and {len(baseline) - 10} more")
    print()

    return baseline


# ─────────────────────────────────────────────
#  Packet dispatcher
# ─────────────────────────────────────────────

def packet_handler(pkt, arp_det: ARPSpoofDetector) -> None:
    """Route each captured ARP packet to the ARP detector."""
    if pkt.haslayer(ARP):
        arp_det.process(pkt)


# ─────────────────────────────────────────────
#  Graceful shutdown
# ─────────────────────────────────────────────

# Module-level references so they can be accessed by the dashboard or signal handlers
_firewall_ref: "FirewallManager | None" = None
_arp_det_ref: "ARPSpoofDetector | None" = None
_host_ip: str = "0.0.0.0"
_host_mac: str = "00:00:00:00:00:00"
_gateway_ip: str = "0.0.0.0"
_iface_desc: str = "Unknown"


def _cleanup_on_exit() -> None:
    """Called by atexit and the signal handler to remove all firewall rules."""
    global _firewall_ref
    if _firewall_ref is not None:
        _firewall_ref.unblock_all()
        _firewall_ref = None  # prevent double-cleanup


def signal_handler(sig, frame):
    print("\n\n[!] Shutting down LAN-Shield …")
    Logger.log_event("SYSTEM", "0.0.0.0", "LAN-Shield stopped by user (Ctrl+C)")
    _cleanup_on_exit()
    sys.exit(0)


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    # ── Platform check ────────────────────────────────────────────────
    if sys.platform != "win32":
        print("[ERROR] This is the Windows edition. Use the Linux version on Kali/Ubuntu.")
        sys.exit(1)

    # ── Admin privilege check ─────────────────────────────────────────
    if not _is_admin():
        print("=" * 60)
        print("  [ERROR] Administrator privileges required.")
        print()
        print("  How to fix:")
        print("    1. Open PowerShell or cmd as Administrator")
        print("       (right-click -> 'Run as administrator')")
        print("    2. Navigate to this folder")
        print("    3. Run:  python main.py")
        print("=" * 60)
        sys.exit(1)

    global _host_ip, _host_mac, _gateway_ip, _iface_desc, _firewall_ref, _arp_det_ref
    signal.signal(signal.SIGINT, signal_handler)

    # ── Step 1: environment detection ───────────────────────────
    host_ip    = get_host_ip()
    interface  = get_best_interface(host_ip)
    iface_desc = describe_interface(interface)
    gateway_ip = get_gateway_ip()

    try:
        host_mac = get_if_hwaddr(interface).lower()
    except Exception:
        host_mac = "00:00:00:00:00:00"

    _host_ip = host_ip
    _host_mac = host_mac
    _gateway_ip = gateway_ip
    _iface_desc = iface_desc

    # ── Print startup banner ─────────────────────────────────────
    print("=" * 65)
    print("     LAN-Shield IDS/IPS  –  Real-Time Protection (Windows)")
    print("=" * 65)
    print(f"  Host IP       : {host_ip}")
    print(f"  Host MAC      : {host_mac}")
    print(f"  Gateway IP    : {gateway_ip}")
    print(f"  Interface     : {iface_desc}")
    print(f"  Block TTL     : {Config.BLOCK_DURATION}s")
    print(f"  Log file      : {Config.LOG_FILE}")
    print("=" * 65)
    print_interfaces()

    print("  Detects: ARP Spoof | Gateway Hijack")
    print("  Blocks via: Windows Firewall (netsh advfirewall)")
    print("  [Ctrl+C to stop]\n")

    Logger.log_event(
        "SYSTEM", host_ip,
        f"LAN-Shield started — iface='{iface_desc}' gw={gateway_ip}"
    )

    # ── Step 2: initialise subsystems ───────────────────────────
    firewall = FirewallManager()
    _firewall_ref = firewall          # expose to shutdown handler
    atexit.register(_cleanup_on_exit) # safety net for any sys.exit() path
    arp_det  = ARPSpoofDetector(host_ip, host_mac, gateway_ip, firewall)
    _arp_det_ref = arp_det

    # ── Step 3: ARP scan → build verified baseline ───────────────
    # This MUST happen before sniff() starts so the baseline is
    # ground-truth and not poisoned by ambient attacker traffic.
    baseline = build_arp_baseline(interface, host_ip)

    # Always include the gateway in the baseline if we got a MAC for it
    # (gateway is the most critical entry — we need it pinned)
    if gateway_ip not in baseline:
        # Send a targeted probe just for the gateway
        try:
            gw_probe = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
            ans, _   = srp(gw_probe, iface=interface, timeout=2, verbose=False)
            if ans:
                gw_mac = ans[0][1][ARP].hwsrc.lower()
                if gw_mac not in ("00:00:00:00:00:00",):
                    baseline[gateway_ip] = gw_mac
                    print(f"[*] Gateway baseline pinned: {gateway_ip} → {gw_mac}")
        except Exception as e:
            Logger.log_event("SYSTEM", "0.0.0.0", f"Gateway probe failed: {e}")

    # Inject baseline into the detector
    arp_det.seed_baseline(baseline)

    # ── Step 4: Flask dashboard ───────────────────────────────────
    if Config.ENABLE_DASHBOARD:
        from dashboard import start_dashboard
        dash_thread = threading.Thread(target=start_dashboard, daemon=True)
        dash_thread.start()
        print(f"[*] Dashboard → http://127.0.0.1:{Config.DASHBOARD_PORT}")
        print(f"    LAN access  → http://{host_ip}:{Config.DASHBOARD_PORT}\n")

    # ── Step 5: start packet capture (blocking) ───────────────────
    print(f"[*] Sniffing on '{iface_desc}' …\n")

    sniff(
        iface   = interface,
        prn     = lambda pkt: packet_handler(pkt, arp_det),
        store   = False,          # never buffer packets in RAM
        filter  = "arp",          # BPF: ARP frames only
    )


if __name__ == "__main__":
    main()
