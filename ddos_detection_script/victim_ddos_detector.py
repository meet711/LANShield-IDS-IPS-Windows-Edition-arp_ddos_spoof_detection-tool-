#!/usr/bin/env python3
"""
victim_ddos_detector.py  –  Host-Based DDoS Detector  (Windows + Linux)
=========================================================================

CORE DESIGN PRINCIPLE: ZERO FIXED THRESHOLDS
─────────────────────────────────────────────
Every machine and every network has a different "normal".
A university web server might see 2000 SYN/s as normal.
A home lab VM might see 5 SYN/s as normal.
Using the same fixed number (e.g. SYN_FLOOR=100) for both machines
WILL either miss attacks on the server or generate constant false
positives on the home lab.

This detector solves that by LEARNING what is normal FOR THIS MACHINE
before it ever fires an alert.

HOW THE BASELINE LEARNING WORKS
─────────────────────────────────
Phase 1 — LEARNING  (first LEARNING_WINDOWS windows, default 20 × 5s = 100s)
  • Packets are counted normally but NO alerts ever fire.
  • After each window, the observed global rate for each protocol
    (SYN / UDP / ICMP / TOTAL packets per window) is recorded into a
    sliding history buffer.

Phase 2 — ACTIVE detection  (after learning phase)
  • For each source IP in a window, compute its per-protocol counts.
  • Compare against a dynamic threshold derived from the learned baseline:
        threshold = baseline_mean + SENSITIVITY × baseline_stddev
  • SENSITIVITY is tunable (default 3.0) — the standard "3-sigma" rule.
    ~99.7% of normal traffic falls within 3σ, so anything beyond is
    statistically abnormal regardless of the absolute packet count.
  • The threshold updates every window as new normal data arrives,
    so it adapts to long-term traffic pattern changes (day vs. night,
    software update bursts, video calls, etc.).

PER-SOURCE ANOMALY, NOT GLOBAL RATE
─────────────────────────────────────
The threshold is derived from the GLOBAL (all-source combined) rate,
but detection fires on INDIVIDUAL SOURCE IPs.

A machine with normal SYN rate of 50/window has threshold ≈ 50 + 3×σ.
A single source sending 500 SYN/window clearly exceeds that.
Meanwhile, those 50 SYN split across 10 legitimate sources (5 each)
never exceeds the threshold — no false positives.

CONFIRMATION GATE — requires N consecutive anomalous windows
──────────────────────────────────────────────────────────────
A source IP must exceed its threshold in CONFIRM_WINDOWS consecutive
windows (default 2) before an alert fires.
This absorbs legitimate traffic spikes (software updates starting,
video calls beginning) that are transient and then return to normal.
A real flood persists across windows and still triggers the gate.

SYN RATIO GUARD — catches pure SYN floods even with low packet counts
───────────────────────────────────────────────────────────────────────
If ≥85% of packets from a source are bare SYN AND the count exceeds
SYN_RATIO_MIN_COUNT, it is flagged immediately (bypasses confirmation gate).
A legitimate host — even a busy web client — virtually never has 85%+ SYN
ratio because it also sends ACK / data / FIN packets.

THREAD MODEL
─────────────
  sniff() thread      → process(pkt)   — updates _counters (brief lock)
  evaluation thread   → _eval_loop()   — wakes every TIME_WINDOW seconds:
                                          snapshots counters, updates baseline,
                                          runs checks, fires alerts
  alert threads       → _fire()        — firewall + notifier + inspector
                                          all in separate daemon threads

PLATFORMS
──────────
  Linux   → iptables  (requires root)
  Windows → netsh advfirewall  (requires Administrator + Npcap)

REQUIREMENTS
────────────
  Linux:
    sudo apt install libnotify-bin   # notify-send desktop alerts
    pip3 install scapy requests

  Windows (run as Administrator):
    pip install scapy requests
    pip install win10toast           # optional desktop toasts
    Npcap: https://npcap.com  (check "WinPcap API-compatible Mode")

USAGE
─────
  # Linux (root required for packet capture + iptables)
  sudo python3 victim_ddos_detector.py

  # Windows (Administrator required for Npcap + netsh)
  python victim_ddos_detector.py

  # You MUST supply the admin/inspector IP (prompted interactively if omitted)
  sudo python3 victim_ddos_detector.py --admin 192.168.56.101
  python      victim_ddos_detector.py --admin 192.168.1.50 --port 5000

  # Tune sensitivity at runtime
  sudo python3 victim_ddos_detector.py --admin 192.168.56.101 --learn 30 --sensitivity 2.5

  NOTE: The admin IP is excluded from host-IP auto-detection, so the victim
        machine will never mis-identify itself as the inspector.
"""

# ─────────────────────────────────────────────────────────────────
#  Standard library
# ─────────────────────────────────────────────────────────────────
import sys
import os
import atexit
import math
import time
import signal
import socket
import logging
import argparse
import threading
import subprocess
import ipaddress
from collections import defaultdict, deque
from datetime    import datetime
from typing      import Optional, Deque

# ─────────────────────────────────────────────────────────────────
#  Third-party imports  (graceful degradation on missing packages)
# ─────────────────────────────────────────────────────────────────
try:
    import requests as _req
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False
    print("[WARN] 'requests' not installed — HTTP alerts to inspector disabled.")
    print("       Fix: pip install requests\n")

try:
    from scapy.all import sniff, get_if_addr, conf, IFACES
    from scapy.all import IP, TCP, UDP, ICMP
except ImportError:
    print("[ERROR] Scapy not installed.")
    print("        Linux:   pip3 install scapy")
    print("        Windows: pip  install scapy  (+ Npcap from https://npcap.com)")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────
#  Platform flags
# ─────────────────────────────────────────────────────────────────
_IS_WINDOWS = sys.platform == "win32"
_IS_LINUX   = sys.platform.startswith("linux")


# ═════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════

class Config:

    # ── Time window ───────────────────────────────────────────────
    # How long each measurement window lasts (seconds).
    # 5s is a good balance between reactivity and noise.
    TIME_WINDOW: int = 5

    # ── Learning phase ────────────────────────────────────────────
    # Number of windows to observe silently before any alert can fire.
    # 20 windows × 5s = 100 seconds of learning.
    # Increase on high-traffic or highly variable networks.
    LEARNING_WINDOWS: int = 20

    # ── Baseline history depth ────────────────────────────────────
    # How many past windows to keep for mean/stddev calculation.
    # 60 windows × 5s = last 5 minutes of traffic history.
    BASELINE_HISTORY: int = 60

    # ── Sensitivity (sigma multiplier) ────────────────────────────
    # threshold = mean + SENSITIVITY × stddev
    #
    # 3.0 = standard 3-sigma rule (recommended starting point)
    # Higher (e.g. 4.0) → fewer false positives, may miss subtle attacks
    # Lower  (e.g. 2.0) → catches more attacks, higher false positive risk
    SENSITIVITY: float = 3.0

    # ── Confirmation gate ─────────────────────────────────────────
    # A source IP must exceed its threshold in this many CONSECUTIVE
    # windows before an alert fires and a block is applied.
    # 2 = recommended (absorbs one-window legitimate bursts)
    # 1 = fire on first anomalous window (faster, noisier)
    CONFIRM_WINDOWS: int = 2

    # ── Minimum packets to evaluate ───────────────────────────────
    # Source IPs with fewer packets in a window are completely ignored.
    # Prevents flagging a host that happened to send 3 SYN packets.
    MIN_PACKETS_TO_EVALUATE: int = 20

    # ── SYN ratio guard ───────────────────────────────────────────
    # If this fraction of a source's packets are bare SYN,
    # flag as SYN flood regardless of rate (bypasses confirmation gate).
    SYN_RATIO_THRESHOLD: float = 0.85

    # ── Minimum SYN count for ratio guard ─────────────────────────
    # Ratio guard only fires if source also sent at least this many SYNs.
    # Lowered from 30 → 10: hping3 --flood easily sends 10+ SYNs/window
    # even at moderate rates; 30 was too conservative for lab/VM networks.
    SYN_RATIO_MIN_COUNT: int = 10

    # ── Absolute floor thresholds ─────────────────────────────────
    # When the baseline is nearly zero (idle machine during learning),
    # mean + 3σ collapses toward 0 and never fires even during a flood.
    # These floors guarantee detection regardless of baseline state.
    # Values are per TIME_WINDOW (5s): 50 SYN/5s = 10 SYN/s minimum.
    SYN_FLOOR:   int = 50    # fire if any source exceeds this SYN count/window
    UDP_FLOOR:   int = 100   # fire if any source exceeds this UDP count/window
    ICMP_FLOOR:  int = 50    # fire if any source exceeds this ICMP count/window
    TOTAL_FLOOR: int = 200   # fire if any source exceeds this total count/window

    # ── Firewall auto-unblock ─────────────────────────────────────
    BLOCK_DURATION: int = 120   # seconds; set 0 to disable auto-unblock

    # ── Inspector (central Windows ARP system) ────────────────────
    INSPECTOR_IP:   str = "192.168.56.1"   # ← your inspector's LAN IP
    INSPECTOR_PORT: int = 5000
    INSPECTOR_PATH: str = "/alert"

    # ── Local log ─────────────────────────────────────────────────
    LOG_FILE: str = "ddos_victim.log"

    # ── Firewall rule prefix (Windows netsh) ──────────────────────
    FW_RULE_PREFIX: str = "NETSHIELD_DDOS_BLOCK_"

    # ── IP whitelist ──────────────────────────────────────────────
    # These prefixes are never counted, evaluated, or blocked.
    WHITELIST_PREFIXES: tuple = (
        "8.8.",    "8.8.4.",   # Google DNS
        "1.1.1.",  "1.0.0.",   # Cloudflare DNS
        "9.9.9.",              # Quad9 DNS
    )


# ═════════════════════════════════════════════════════════════════
#  LOGGER
# ═════════════════════════════════════════════════════════════════

class Logger:
    """Thread-safe: writes to log file AND colour-coded console."""

    _lock = threading.Lock()

    logging.basicConfig(
        filename = Config.LOG_FILE,
        level    = logging.INFO,
        format   = "%(asctime)s  %(message)s",
        datefmt  = "%Y-%m-%d %H:%M:%S",
    )

    _RED    = "\033[91m"
    _YELLOW = "\033[93m"
    _CYAN   = "\033[96m"
    _RESET  = "\033[0m"

    @classmethod
    def log(cls, event: str, ip: str, detail: str) -> None:
        msg    = f"[{event:<12}] {ip:<18} {detail}"
        ts     = datetime.now().strftime("%H:%M:%S")
        colour = (
            cls._RED    if event in ("DDOS", "BLOCK")   else
            cls._YELLOW if event in ("WARN", "SUSPECT") else
            cls._CYAN
        )
        with cls._lock:
            logging.info(msg)
            print(f"{colour}[{ts}] {msg}{cls._RESET}")

    @classmethod
    def info(cls, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        with cls._lock:
            logging.info(msg)
            print(f"{cls._CYAN}[{ts}] {msg}{cls._RESET}")


# ═════════════════════════════════════════════════════════════════
#  SYSTEM NOTIFIER
# ═════════════════════════════════════════════════════════════════

class Notifier:
    """
    Cross-platform desktop notification.
    Linux   → notify-send  (requires: sudo apt install libnotify-bin)
    Windows → win10toast   (requires: pip install win10toast)
              falls back to a console bell if win10toast is absent.
    """

    _win_toast = None
    if _IS_WINDOWS:
        try:
            from win10toast import ToastNotifier
            _win_toast = ToastNotifier()
        except ImportError:
            pass

    @classmethod
    def alert(cls, title: str, message: str) -> None:
        threading.Thread(
            target=cls._send, args=(title, message), daemon=True
        ).start()

    @classmethod
    def _send(cls, title: str, message: str) -> None:
        try:
            if _IS_LINUX:
                subprocess.run(
                    ["notify-send", "-u", "critical", "-t", "8000",
                     title, message],
                    check=False,
                )
            elif _IS_WINDOWS:
                if cls._win_toast is not None:
                    cls._win_toast.show_toast(
                        title, message, duration=10, threaded=False
                    )
                else:
                    print(f"\a\n{'!'*60}\n  {title}\n  {message}\n{'!'*60}\n")
        except Exception as exc:
            Logger.log("NOTIFY_ERR", "local", str(exc))


# ═════════════════════════════════════════════════════════════════
#  FIREWALL MANAGER
# ═════════════════════════════════════════════════════════════════

class FirewallManager:
    """
    Cross-platform firewall wrapper.
    Linux   → iptables -I INPUT -s <ip> -j DROP
    Windows → netsh advfirewall firewall add rule dir=in action=block
    Thread-safe. Auto-unblock after BLOCK_DURATION seconds.
    """

    def __init__(self) -> None:
        self._blocked: dict[str, str] = {}   # ip → timestamp string
        self._lock = threading.Lock()
        self._check_privileges()

    # ── Public API ────────────────────────────────────────────────

    def block(self, ip: str, reason: str = "") -> None:
        with self._lock:
            if ip in self._blocked:
                return
            self._blocked[ip] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if _IS_LINUX:
            self._ipt_block(ip)
        else:
            self._netsh_block(ip)

        Logger.log(
            "BLOCK", ip,
            f"Reason: {reason}. Auto-unblock in {Config.BLOCK_DURATION}s."
        )

        if Config.BLOCK_DURATION > 0:
            t = threading.Timer(Config.BLOCK_DURATION, self._auto_unblock, args=(ip,))
            t.daemon = True
            t.start()

    def unblock(self, ip: str) -> None:
        with self._lock:
            if ip not in self._blocked:
                return
            del self._blocked[ip]
        if _IS_LINUX:
            self._ipt_unblock(ip)
        else:
            self._netsh_unblock(ip)
        Logger.log("UNBLOCK", ip, "Manual unblock.")

    def unblock_all(self) -> None:
        """Unblock every currently-blocked IP – called on program exit."""
        with self._lock:
            ips = list(self._blocked.keys())

        if not ips:
            return

        print(f"[FirewallManager] Cleaning up {len(ips)} blocked IP(s) on exit …")
        for ip in ips:
            if _IS_LINUX:
                self._ipt_unblock(ip)
            else:
                self._netsh_unblock(ip)
            Logger.log("UNBLOCK", ip, "Unblocked on program exit")

        with self._lock:
            self._blocked.clear()

        print("[FirewallManager] All firewall rules cleaned up.")

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    # ── Private ───────────────────────────────────────────────────

    def _auto_unblock(self, ip: str) -> None:
        with self._lock:
            if ip not in self._blocked:
                return
            del self._blocked[ip]
        if _IS_LINUX:
            self._ipt_unblock(ip)
        else:
            self._netsh_unblock(ip)
        Logger.log("UNBLOCK", ip, f"Auto-unblocked after {Config.BLOCK_DURATION}s.")

    def _check_privileges(self) -> None:
        try:
            if _IS_LINUX and os.geteuid() != 0:
                print(
                    "[FirewallManager] WARNING: not root — iptables will fail.\n"
                    "  Run: sudo python3 victim_ddos_detector.py\n"
                    "  Detection + alerts still work.\n"
                )
            elif _IS_WINDOWS:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print(
                        "[FirewallManager] WARNING: not Administrator — netsh will fail.\n"
                        "  Right-click PowerShell → Run as administrator.\n"
                        "  Detection + alerts still work.\n"
                    )
        except Exception:
            pass

    # ── iptables (Linux) ──────────────────────────────────────────

    @staticmethod
    def _ipt_block(ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            Logger.log("FW_ERR", ip, f"iptables block failed: {e.stderr.strip()}")

    @staticmethod
    def _ipt_unblock(ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError:
            pass

    # ── netsh advfirewall (Windows) ───────────────────────────────

    @staticmethod
    def _rule_name(ip: str) -> str:
        return f"{Config.FW_RULE_PREFIX}{ip.replace('.', '_')}"

    @classmethod
    def _netsh_block(cls, ip: str) -> None:
        rule = cls._rule_name(ip)
        cmd  = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes", "profile=any",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            Logger.log("FW_ERR", ip, f"netsh block failed: {e.stderr.strip()}")

    @classmethod
    def _netsh_unblock(cls, ip: str) -> None:
        rule = cls._rule_name(ip)
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule}"],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError:
            pass


# ═════════════════════════════════════════════════════════════════
#  INSPECTOR CLIENT
# ═════════════════════════════════════════════════════════════════

class InspectorClient:
    """
    Fire-and-forget HTTP POST to the central admin dashboard.
    Runs in a daemon thread — a dead inspector never stalls detection.

    NOTE: _url is built lazily (via property) so it always reads the
    current Config values, even if Config was updated after __init__.
    """

    def __init__(self, victim_ip: str) -> None:
        self._victim_ip = victim_ip
        # Do NOT cache the URL here — Config.INSPECTOR_IP/PORT are set
        # in main() AFTER this object might be constructed in some flows.

    @property
    def _url(self) -> str:
        """Always reflects the current Config (never stale)."""
        return (
            f"http://{Config.INSPECTOR_IP}:{Config.INSPECTOR_PORT}"
            f"{Config.INSPECTOR_PATH}"
        )

    def send(self, attacker_ip: str, attack_type: str, packet_count: int) -> None:
        payload = {
            "attacker_ip":  attacker_ip,
            "victim_ip":    self._victim_ip,
            "attack_type":  attack_type,
            "packet_count": packet_count,
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        threading.Thread(
            target=self._post, args=(payload,), daemon=True
        ).start()

    def _post(self, payload: dict) -> None:
        if not _REQUESTS_OK:
            return
        try:
            r = _req.post(self._url, json=payload, timeout=3)
            Logger.log(
                "INSPECTOR", payload["attacker_ip"],
                f"Alert POSTed → {self._url}  HTTP {r.status_code}"
            )
        except _req.exceptions.ConnectionError:
            Logger.log(
                "INSPECTOR", payload["attacker_ip"],
                f"Inspector unreachable at {self._url}"
            )
        except Exception as exc:
            Logger.log("INSPECTOR", payload["attacker_ip"], f"POST failed: {exc}")


# ═════════════════════════════════════════════════════════════════
#  ADAPTIVE BASELINE ENGINE
# ═════════════════════════════════════════════════════════════════

class _ProtocolBaseline:
    """
    Tracks the normal rate for ONE metric (e.g., SYN packets per window)
    using a sliding history deque.

    Every TIME_WINDOW seconds, call update(observed_rate).
    Call threshold() to get the current detection threshold:
        threshold = mean + SENSITIVITY × stddev

    Returns float('inf') until MIN_SAMPLES samples have been collected,
    so nothing ever fires during the very early learning phase.
    """

    MIN_SAMPLES: int = 5   # need at least 5 data points for a meaningful stddev

    def __init__(self) -> None:
        # maxlen enforces the sliding window — oldest values drop off automatically
        self._history: Deque[float] = deque(maxlen=Config.BASELINE_HISTORY)

    def update(self, rate: float) -> None:
        """Add one window's observed rate to the history."""
        self._history.append(max(rate, 0.0))   # never store negative rates

    @property
    def mean(self) -> float:
        if not self._history:
            return 0.0
        return sum(self._history) / len(self._history)

    @property
    def stddev(self) -> float:
        n = len(self._history)
        if n < 2:
            return 0.0
        m = self.mean
        # Sample standard deviation (divide by n-1, not n)
        variance = sum((x - m) ** 2 for x in self._history) / (n - 1)
        return math.sqrt(variance)

    def threshold(self, floor: float = 1.0) -> float:
        """
        The alert threshold for this metric.
        Returns float('inf') when there are not enough samples yet,
        which guarantees no false positives during early learning.

        floor — absolute minimum threshold regardless of baseline.
                Prevents a near-zero baseline (idle machine) from
                making the threshold so low it collapses, but also
                prevents it from being so HIGH (baseline poisoned by
                attack traffic during learning) that it never fires.
                Callers pass the per-protocol Config.*_FLOOR value.
        """
        if len(self._history) < self.MIN_SAMPLES:
            # Not enough data yet: use the floor so we can still catch
            # obvious floods even before baseline is established.
            return floor
        t = self.mean + Config.SENSITIVITY * self.stddev
        # Use whichever is LOWER: stat threshold or floor.
        # This prevents a poisoned baseline from raising the bar
        # above the floor that we know is definitely anomalous.
        return min(max(t, 1.0), floor) if t > floor * 3 else max(t, floor * 0.5)

    def summary(self) -> str:
        return (
            f"mean={self.mean:.1f} "
            f"sigma={self.stddev:.1f} "
            f"thr={self.threshold():.1f} "
            f"n={len(self._history)}"
        )


class AdaptiveBaseline:
    """
    Holds per-protocol baselines for the whole machine.

    GLOBAL (all-source combined) rates per window are used to establish
    what 'normal' looks like for this specific machine.
    Per-source checks then compare each individual source against
    those globally derived thresholds.

    Why global?
    ───────────
    Normal traffic on this machine is distributed across N sources.
    The global rate captures the total load the machine handles normally.
    Any single source that approaches the TOTAL global rate is clearly abnormal —
    it means one IP is sending as much traffic as the entire normal population.
    """

    def __init__(self) -> None:
        self.syn   = _ProtocolBaseline()
        self.udp   = _ProtocolBaseline()
        self.icmp  = _ProtocolBaseline()
        self.total = _ProtocolBaseline()

    def update(
        self,
        global_syn:   float,
        global_udp:   float,
        global_icmp:  float,
        global_total: float,
    ) -> None:
        self.syn.update(global_syn)
        self.udp.update(global_udp)
        self.icmp.update(global_icmp)
        self.total.update(global_total)

    def summary(self) -> str:
        lines = [
            f"  SYN   : {self.syn.summary()}",
            f"  UDP   : {self.udp.summary()}",
            f"  ICMP  : {self.icmp.summary()}",
            f"  TOTAL : {self.total.summary()}",
        ]
        return "\n".join(lines)


# ═════════════════════════════════════════════════════════════════
#  DDOS DETECTOR
# ═════════════════════════════════════════════════════════════════

class DDoSDetector:
    """
    Full pipeline: packet counting → baseline learning → anomaly detection
    → confirmation gating → alert + block.

    States
    ──────
    LEARNING : first LEARNING_WINDOWS evaluation windows.
               All packets are counted. Baseline accumulates.
               Zero alerts fire.
    ACTIVE   : Thresholds are live. Anomalies are gated and fire alerts.
               Baseline continues to update every window so it adapts
               to long-term traffic changes.
    """

    def __init__(
        self,
        host_ip:   str,
        firewall:  FirewallManager,
        inspector: InspectorClient,
    ) -> None:
        self._host_ip   = host_ip
        self._firewall  = firewall
        self._inspector = inspector
        self._local_nets = _get_lan_networks(host_ip)

        # Per-source packet counters for the CURRENT window.
        # Written by sniff() thread, snapshotted + cleared by eval thread.
        # { src_ip: { "syn": int, "udp": int, "icmp_req": int, "total": int } }
        self._counters: dict = defaultdict(
            lambda: {"syn": 0, "udp": 0, "icmp_req": 0, "total": 0}
        )
        self._count_lock = threading.Lock()

        # Adaptive baseline
        self._baseline = AdaptiveBaseline()

        # Learning phase state
        self._windows_seen: int = 0
        self._learning: bool    = True

        # Confirmation gate counters.
        # { src_ip: { "syn": int, "udp": int, "icmp_req": int, "total": int } }
        # Each value = number of CONSECUTIVE windows this source has been
        # above the threshold for that protocol.
        # Resets to 0 as soon as the source drops below threshold.
        self._confirm: dict = defaultdict(
            lambda: {"syn": 0, "udp": 0, "icmp_req": 0, "total": 0}
        )

        # Start background evaluation thread (daemon — exits with main program)
        threading.Thread(target=self._eval_loop, daemon=True).start()

    # ── Packet ingestion (Scapy sniff() callback) ─────────────────

    @staticmethod
    def _is_whitelisted(ip: str) -> bool:
        return any(ip.startswith(pfx) for pfx in Config.WHITELIST_PREFIXES)

    def process(self, pkt) -> None:
        """
        Classify and count one inbound packet.
        Called for every sniffed packet — MUST be extremely fast.
        Only performs integer increments under a brief lock.
        No I/O, no string formatting, no detection logic here.
        """
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src

        # Ignore our own outbound traffic (visible in promiscuous mode)
        if src in (self._host_ip, "127.0.0.1"):
            return

        if self._is_whitelisted(src):
            return

        # Ensure the source IP is from our local LAN (IP class of our network)
        if hasattr(self, '_local_nets') and self._local_nets:
            try:
                src_addr = ipaddress.IPv4Address(src)
                if not any(src_addr in net for net in self._local_nets):
                    return
            except Exception:
                return

        # Don't accumulate counts for already-blocked IPs
        if self._firewall.is_blocked(src):
            return

        with self._count_lock:
            c = self._counters[src]
            c["total"] += 1

            if pkt.haslayer(TCP):
                if pkt[TCP].flags & 0x02:      # SYN bit set
                    c["syn"] += 1
            elif pkt.haslayer(UDP):
                c["udp"] += 1
            elif pkt.haslayer(ICMP):
                if pkt[ICMP].type == 8:        # echo-request only (type 0 = reply)
                    c["icmp_req"] += 1

    # ── Evaluation loop ───────────────────────────────────────────

    def _eval_loop(self) -> None:
        """Background daemon: wakes every TIME_WINDOW seconds."""
        while True:
            time.sleep(Config.TIME_WINDOW)
            self._evaluate()

    def _evaluate(self) -> None:
        """
        One evaluation cycle:
          1. Atomically snapshot + clear current-window counters.
          2. Feed global per-protocol totals into the baseline.
          3. If still learning: log progress, check if learning is done.
          4. If active: run per-source anomaly checks.
          5. Clean up stale confirmation counters.
        """

        # ── Step 1: Atomic snapshot ────────────────────────────────
        # The lock is held only for the copy + clear — no processing inside.
        with self._count_lock:
            snapshot = {ip: dict(c) for ip, c in self._counters.items()}
            self._counters.clear()

        self._windows_seen += 1

        # ── Step 2: Compute GLOBAL rates for this window ──────────
        # Sum all sources together to get the machine's total traffic.
        # Zero if no traffic arrived (still a valid data point).
        global_syn   = float(sum(c["syn"]      for c in snapshot.values()))
        global_udp   = float(sum(c["udp"]      for c in snapshot.values()))
        global_icmp  = float(sum(c["icmp_req"] for c in snapshot.values()))
        global_total = float(sum(c["total"]    for c in snapshot.values()))

        # Always update the baseline — even during learning, even with zero traffic
        self._baseline.update(global_syn, global_udp, global_icmp, global_total)

        # ── Step 3: Learning phase ─────────────────────────────────
        if self._learning:
            remaining = Config.LEARNING_WINDOWS - self._windows_seen

            # ── EARLY EXIT: if floor thresholds are exceeded during
            #    learning, a real attack is already running.  Skip the
            #    rest of learning and arm detection immediately.
            attack_during_learning = any(
                counts["syn"]      >= Config.SYN_FLOOR   or
                counts["udp"]      >= Config.UDP_FLOOR   or
                counts["icmp_req"] >= Config.ICMP_FLOOR  or
                counts["total"]    >= Config.TOTAL_FLOOR
                for counts in snapshot.values()
            )
            if attack_during_learning:
                Logger.info(
                    f"\n[LEARNING ABORTED — ATTACK DETECTED DURING LEARNING]\n"
                    f"  Traffic from one or more sources exceeds floor thresholds.\n"
                    f"  Arming detection NOW (after {self._windows_seen} windows).\n"
                )
                self._learning = False
                # Fall through to active detection below (do NOT return)
            else:
                Logger.info(
                    f"[LEARNING {self._windows_seen:>3}/{Config.LEARNING_WINDOWS}] "
                    f"sources={len(snapshot):>3}  "
                    f"SYN={global_syn:>6.0f}  "
                    f"UDP={global_udp:>6.0f}  "
                    f"ICMP={global_icmp:>6.0f}  "
                    f"TOTAL={global_total:>6.0f}  "
                    f"({'%ds remaining' % (remaining * Config.TIME_WINDOW) if remaining > 0 else 'finalising...'})"
                )
                if self._windows_seen >= Config.LEARNING_WINDOWS:
                    self._learning = False
                    Logger.info(
                        f"\n[LEARNING COMPLETE]  Baseline established over "
                        f"{self._windows_seen * Config.TIME_WINDOW}s.\n"
                        f"  Detection is now ACTIVE.\n"
                        f"{self._baseline.summary()}\n"
                    )
                return   # never check for attacks during normal learning

        # ── Step 4: Active detection ───────────────────────────────
        if not snapshot:
            return   # no traffic this window — nothing to check

        # Pull the current thresholds ONCE (they're computed from history).
        # Passing the Config floor ensures a poisoned or near-zero baseline
        # can never push the threshold above the known-dangerous absolute floor.
        thr_syn   = self._baseline.syn.threshold(floor=float(Config.SYN_FLOOR))
        thr_udp   = self._baseline.udp.threshold(floor=float(Config.UDP_FLOOR))
        thr_icmp  = self._baseline.icmp.threshold(floor=float(Config.ICMP_FLOOR))
        thr_total = self._baseline.total.threshold(floor=float(Config.TOTAL_FLOOR))

        for src_ip, counts in snapshot.items():
            self._check_source(
                src_ip, counts,
                thr_syn, thr_udp, thr_icmp, thr_total,
            )

        # ── Step 5: Stale confirmation cleanup ────────────────────
        # If a source IP was seen previously but sent no packets this window,
        # its confirmation streak must reset — it stopped the attack.
        stale = [ip for ip in list(self._confirm) if ip not in snapshot]
        for ip in stale:
            del self._confirm[ip]

    # ── Per-source anomaly check ──────────────────────────────────

    def _check_source(
        self,
        src_ip:    str,
        counts:    dict,
        thr_syn:   float,
        thr_udp:   float,
        thr_icmp:  float,
        thr_total: float,
    ) -> None:
        """
        Evaluate one source IP against the learned thresholds.

        Uses confirmation gating: the source must exceed its threshold
        in CONFIRM_WINDOWS consecutive windows before _fire() is called.
        This absorbs legitimate one-window bursts (software updates, etc.).

        The SYN ratio guard bypasses the confirmation gate because
        an 85%+ SYN ratio is an unambiguous flood-tool signature.
        """

        # Not enough packets from this source to make a meaningful judgment
        if counts["total"] < Config.MIN_PACKETS_TO_EVALUATE:
            # Also reset any partial confirmation streaks so a source that
            # briefly exceeded the minimum but then went quiet doesn't
            # carry forward a partial count
            self._confirm.pop(src_ip, None)
            return

        total     = counts["total"]
        cc        = self._confirm[src_ip]   # confirmation counters for this source
        syn_ratio = counts["syn"] / total if total > 0 else 0.0

        # ── Helper: update confirmation counter and check if gate opens ──
        def gate(key: str, is_anomalous: bool) -> bool:
            """
            Increment cc[key] if anomalous, reset to 0 if not.
            Returns True only when cc[key] reaches CONFIRM_WINDOWS,
            meaning the anomaly has persisted long enough to be confirmed.
            Fire only ONCE per confirmation (not every subsequent window).
            """
            if is_anomalous:
                cc[key] += 1
            else:
                cc[key] = 0
            # Fire exactly when the counter reaches the threshold (== not >=)
            # so we don't re-fire every window during a sustained attack
            return cc[key] == Config.CONFIRM_WINDOWS

        # ── Signal 1: TCP SYN Flood ────────────────────────────────
        #
        # Two sub-signals — either can fire independently:
        #
        # (a) Rate check: source's SYN count exceeds the threshold derived
        #     from the machine's normal SYN rate.
        #     Goes through the confirmation gate (requires N consecutive windows).
        #
        # (b) Ratio guard: ≥85% of this source's packets are bare SYN,
        #     AND at least SYN_RATIO_MIN_COUNT SYNs were sent.
        #     BYPASSES the confirmation gate — this pattern is unambiguous
        #     (hping3, Scapy floods, nmap SYN scan at high rate).
        syn_ratio_alarm = (
            syn_ratio  >= Config.SYN_RATIO_THRESHOLD
            and counts["syn"] >= Config.SYN_RATIO_MIN_COUNT
        )
        if syn_ratio_alarm:
            # Immediate — no confirmation needed
            self._fire(
                "TCP SYN FLOOD", src_ip, counts,
                f"SYN ratio guard: {counts['syn']} SYNs "
                f"= {syn_ratio:.0%} of {total} total packets  "
                f"(threshold {Config.SYN_RATIO_THRESHOLD:.0%})  "
                f"{self._baseline.syn.summary()}"
            )
        elif gate("syn", counts["syn"] > thr_syn):
            self._fire(
                "TCP SYN FLOOD", src_ip, counts,
                f"SYN={counts['syn']} > thr={thr_syn:.1f}  "
                f"ratio={syn_ratio:.0%}  "
                f"confirmed {Config.CONFIRM_WINDOWS} consecutive windows  "
                f"{self._baseline.syn.summary()}"
            )

        # ── Signal 2: UDP Flood ────────────────────────────────────
        if gate("udp", counts["udp"] > thr_udp):
            self._fire(
                "UDP FLOOD", src_ip, counts,
                f"UDP={counts['udp']} > thr={thr_udp:.1f}  "
                f"confirmed {Config.CONFIRM_WINDOWS} consecutive windows  "
                f"{self._baseline.udp.summary()}"
            )

        # ── Signal 3: ICMP Echo-Request Flood ─────────────────────
        if gate("icmp_req", counts["icmp_req"] > thr_icmp):
            self._fire(
                "ICMP FLOOD", src_ip, counts,
                f"ICMP={counts['icmp_req']} > thr={thr_icmp:.1f}  "
                f"confirmed {Config.CONFIRM_WINDOWS} consecutive windows  "
                f"{self._baseline.icmp.summary()}"
            )

        # ── Signal 4: High-Rate Mixed-Protocol Flood ───────────────
        # Catches flood tools that intentionally spread SYN+UDP+ICMP traffic
        # to stay just below each individual protocol threshold.
        #
        # CRITICAL GUARD: only fires if the source has at least one
        # attack-protocol packet (SYN/UDP/ICMP).
        # Pure TCP data-response traffic (ACK / data segments) has
        # syn=0 udp=0 icmp=0.  Without this guard, a CDN sending a large
        # TCP download burst would be incorrectly flagged.
        already_fired    = (cc["syn"]      >= Config.CONFIRM_WINDOWS or
                            cc["udp"]      >= Config.CONFIRM_WINDOWS or
                            cc["icmp_req"] >= Config.CONFIRM_WINDOWS or
                            syn_ratio_alarm)
        attack_protos    = counts["syn"] + counts["udp"] + counts["icmp_req"]

        if not already_fired and attack_protos > 0:
            if gate("total", total > thr_total):
                self._fire(
                    "HIGH-RATE MIXED FLOOD", src_ip, counts,
                    f"TOTAL={total} > thr={thr_total:.1f}  "
                    f"SYN={counts['syn']}  UDP={counts['udp']}  "
                    f"ICMP={counts['icmp_req']}  "
                    f"confirmed {Config.CONFIRM_WINDOWS} consecutive windows  "
                    f"{self._baseline.total.summary()}"
                )

    # ── Alert dispatcher ──────────────────────────────────────────

    def _fire(
        self,
        attack_type: str,
        src_ip:      str,
        counts:      dict,
        detail:      str,
    ) -> None:
        """
        Confirmed attack:
          1. Log to file + console  (synchronous)
          2. Block via firewall     (synchronous — fast subprocess)
          3. Desktop notification   (daemon thread — never blocks)
          4. HTTP to inspector      (daemon thread — never blocks)
          5. Reset confirmation counters so a re-attack must be re-confirmed
        """
        Logger.log("DDOS", src_ip, f"[{attack_type}] {detail}")

        if not self._firewall.is_blocked(src_ip):
            self._firewall.block(src_ip, reason=attack_type)

        Notifier.alert(
            title   = "⚠️  DDoS Attack Detected!",
            message = (
                f"Source   : {src_ip}\n"
                f"Type     : {attack_type}\n"
                f"Packets  : {counts['total']}\n"
                f"Blocked  : ✓"
            ),
        )

        self._inspector.send(
            attacker_ip  = src_ip,
            attack_type  = attack_type,
            packet_count = counts["total"],
        )

        # Reset confirmation so a resumed attack must be re-confirmed —
        # prevents repeated alerts from firing every window during a sustained attack
        self._confirm.pop(src_ip, None)


# ═════════════════════════════════════════════════════════════════
#  INTERFACE / IP HELPERS
# ═════════════════════════════════════════════════════════════════

def _get_lan_networks(host_ip: str) -> list:
    """Return the private IPv4 networks (or IP class bounds) attached to this machine."""
    nets = []
    try:
        from scapy.all import conf
        import socket
        import struct
        for route in conf.route.routes:
            dest = route[0]
            mask = route[1]
            if dest != 0 and mask != 0 and mask != 4294967295 and not (dest & 0xF0000000 == 0xE0000000):
                net_str = f"{socket.inet_ntoa(struct.pack('!I', dest))}/{socket.inet_ntoa(struct.pack('!I', mask))}"
                net = ipaddress.IPv4Network(net_str, strict=False)
                if net.is_private and net not in nets:
                    nets.append(net)
    except Exception:
        pass

    # Fallback to classful network of host_ip if routing table logic misses it
    if host_ip and host_ip != "127.0.0.1":
        try:
            addr = ipaddress.IPv4Address(host_ip)
            first_octet = int(str(addr).split('.')[0])
            fallback_net = None
            if 1 <= first_octet <= 126: # Class A
                fallback_net = ipaddress.IPv4Network(f"{first_octet}.0.0.0/8", strict=False)
            elif 128 <= first_octet <= 191: # Class B
                fallback_net = ipaddress.IPv4Network(f"{str(addr).rsplit('.', 2)[0]}.0.0/16", strict=False)
            elif 192 <= first_octet <= 223: # Class C
                fallback_net = ipaddress.IPv4Network(f"{str(addr).rsplit('.', 1)[0]}.0/24", strict=False)
            
            if fallback_net and fallback_net not in nets:
                nets.append(fallback_net)
        except Exception:
            pass

    return nets


def _ip_rank(ip_str: str) -> int:
    """
    Lower = better (preferred). 999 = unusable.

    Ranking is tightened vs the original:
      - All 192.168.* addresses are NOT equal — the one reachable via
        the default route scores best (rank 0); others score 1.
        This prevents a VirtualBox host-only adapter from outranking
        the real bridged/NAT adapter just by alphabetical IFACE order.
      - 10.x / 172.16.x still score 2/3 as fallback private ranges.
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except Exception:
        return 999
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return 999
    if str(addr) == "255.255.255.255":
        return 999
    # Prefer the IP that the OS would use to reach the internet
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
            _s.connect(("8.8.8.8", 80))
            default_route_ip = _s.getsockname()[0]
        if ip_str == default_route_ip:
            return 0     # best: this is the default-route interface
    except Exception:
        pass
    if ip_str.startswith("192.168."):
        return 1         # other 192.168.* (e.g. host-only adapter)
    if ip_str.startswith("10."):
        return 2
    if addr in ipaddress.IPv4Network("172.16.0.0/12"):
        return 3
    return 9


def _get_host_ip(exclude_ip: str = "") -> str:
    """
    Return the best LAN IP of this machine.

    exclude_ip — the admin/inspector IP.  Any interface whose address
    exactly matches exclude_ip is skipped, preventing the victim from
    mis-identifying itself as the inspector when they share a subnet
    (common with VirtualBox host-only adapters).
    """
    candidates = []
    try:
        for name in IFACES:
            try:
                ip   = get_if_addr(name)
                if ip == exclude_ip:          # never pick the admin's IP
                    continue
                rank = _ip_rank(ip)
                if rank < 999:
                    candidates.append((rank, ip))
            except Exception:
                continue
    except Exception:
        pass
    if candidates:
        return sorted(candidates)[0][1]
    # UDP-trick fallback (no packet is actually sent)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip != exclude_ip:
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def _best_interface(host_ip: str) -> Optional[str]:
    """Return the Scapy interface name whose address matches host_ip, or None."""
    best_name = None
    best_rank = 999
    try:
        for name in IFACES:
            try:
                ip   = get_if_addr(name)
                rank = _ip_rank(ip)
                if ip == host_ip and rank < best_rank:
                    best_rank = rank
                    best_name = name
            except Exception:
                continue
    except Exception:
        pass
    return best_name


# ═════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════

def _prompt_admin_config(have_ip: bool, have_port: bool) -> tuple:
    """
    Interactively ask for any missing admin connection details.
    Returns (admin_ip: str, admin_port: int).

    have_ip   — True if --admin was already supplied on the CLI
    have_port — True if --port was already supplied on the CLI

    Only the missing values are prompted; already-supplied ones are skipped.
    """
    print()
    print("  ┌──────────────────────────────────────────────────────────┐")
    print("  │  NetShield — Admin Dashboard Connection Setup            │")
    print("  │  Alerts are POSTed to  http://<ADMIN_IP>:<PORT>/alert    │")
    print("  └──────────────────────────────────────────────────────────┘")

    # ── IP ────────────────────────────────────────────────────────────
    admin_ip = None
    if not have_ip:
        while True:
            try:
                raw = input("  Enter admin IP   (e.g. 192.168.1.50)      : ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Aborted.")
                sys.exit(0)
            try:
                ipaddress.IPv4Address(raw)
                admin_ip = raw
                break
            except ValueError:
                print(f"  [!] '{raw}' is not a valid IPv4 address. Try again.")

    # ── Port ──────────────────────────────────────────────────────────
    admin_port = None
    if not have_port:
        while True:
            try:
                raw = input(f"  Enter admin port (press Enter for {Config.INSPECTOR_PORT}) : ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Aborted.")
                sys.exit(0)
            if raw == "":
                admin_port = Config.INSPECTOR_PORT   # accept default on Enter
                break
            try:
                p = int(raw)
                if 1 <= p <= 65535:
                    admin_port = p
                    break
                else:
                    print("  [!] Port must be between 1 and 65535.")
            except ValueError:
                print(f"  [!] '{raw}' is not a valid port number. Try again.")

    return admin_ip, admin_port


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "NetShield Victim DDoS Detector  (Windows + Linux)\n"
            "Learns your machine's normal traffic, then alerts on deviations.\n\n"
            "The --admin flag (inspector/dashboard IP) is required.\n"
            "If omitted you will be prompted interactively at startup."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--admin", "-a",
        metavar="IP",
        default=None,
        help=(
            "IP address of the central admin / NetShield dashboard machine. "
            "DDoS alerts are POSTed to http://<ADMIN>:<PORT>/alert. "
            "This IP is also excluded from victim host-IP auto-detection so "
            "the machine never mis-identifies itself as the inspector. "
            "(prompted interactively if not supplied)"
        ),
    )
    # Keep --inspector as a hidden alias for backwards compatibility
    parser.add_argument("--inspector", "-i", metavar="IP", default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument(
        "--port", "-p",
        metavar="PORT",
        type=int,
        default=Config.INSPECTOR_PORT,
        help=f"Admin dashboard HTTP port (default: {Config.INSPECTOR_PORT})",
    )
    parser.add_argument(
        "--learn", "-l",
        metavar="N",
        type=int,
        default=Config.LEARNING_WINDOWS,
        help=(
            f"Learning windows before detection arms "
            f"(default: {Config.LEARNING_WINDOWS} = "
            f"{Config.LEARNING_WINDOWS * Config.TIME_WINDOW}s)"
        ),
    )
    parser.add_argument(
        "--sensitivity", "-s",
        metavar="SIGMA",
        type=float,
        default=Config.SENSITIVITY,
        help=(
            f"Alert at mean + SIGMA×stddev "
            f"(default: {Config.SENSITIVITY};  higher = fewer false positives)"
        ),
    )
    parser.add_argument(
        "--confirm", "-c",
        metavar="N",
        type=int,
        default=Config.CONFIRM_WINDOWS,
        help=(
            f"Consecutive anomalous windows before alert fires "
            f"(default: {Config.CONFIRM_WINDOWS})"
        ),
    )
    return parser.parse_args()


# Module-level firewall reference for shutdown cleanup
_fw_ref: "FirewallManager | None" = None


def _cleanup_on_exit() -> None:
    """Remove all Windows Firewall / iptables rules added during this session."""
    global _fw_ref
    if _fw_ref is not None:
        _fw_ref.unblock_all()
        _fw_ref = None  # prevent double-cleanup


def _shutdown(sig, frame):
    print("\n[!] Shutting down victim DDoS detector …")
    Logger.log("SYSTEM", "local", "Detector stopped by user.")
    _cleanup_on_exit()
    sys.exit(0)


def main() -> None:
    args = _parse_args()

    # ── Resolve admin IP + port ──────────────────────────────────────
    # Priority: CLI flags → legacy --inspector → interactive prompt
    admin_ip   = args.admin or args.inspector   # None if neither supplied
    admin_port = args.port                      # always has a default value

    # Detect which values still need prompting
    need_ip   = admin_ip is None
    # Prompt for port too if it was not explicitly passed on the CLI
    # (args.port always has a value from argparse default, so we track
    #  whether the user actually typed --port by checking sys.argv)
    need_port = "--port" not in sys.argv and "-p" not in sys.argv

    if need_ip or need_port:
        prompted_ip, prompted_port = _prompt_admin_config(
            have_ip   = not need_ip,
            have_port = not need_port,
        )
        if need_ip:
            admin_ip = prompted_ip
        if need_port:
            admin_port = prompted_port

    # Validate IP (covers the --inspector alias path)
    try:
        ipaddress.IPv4Address(admin_ip)
    except ValueError:
        print(f"[ERROR] '{admin_ip}' is not a valid IPv4 address.")
        sys.exit(1)

    # Apply to config
    Config.INSPECTOR_IP     = admin_ip
    Config.INSPECTOR_PORT   = admin_port
    Config.LEARNING_WINDOWS = args.learn
    Config.SENSITIVITY      = args.sensitivity
    Config.CONFIRM_WINDOWS  = args.confirm

    signal.signal(signal.SIGINT, _shutdown)

    # ── Detect victim IP, explicitly excluding the admin IP ──────────
    # This prevents the machine from picking the VirtualBox host-only
    # adapter (which shares a subnet with the admin) as its own identity.
    host_ip = _get_host_ip(exclude_ip=admin_ip)
    iface   = _best_interface(host_ip)

    platform_str = "Windows" if _IS_WINDOWS else "Linux"
    fw_backend   = "netsh advfirewall" if _IS_WINDOWS else "iptables"
    learn_secs   = Config.LEARNING_WINDOWS * Config.TIME_WINDOW

    print("=" * 70)
    print(f"  NetShield — Victim DDoS Detector  ({platform_str})")
    print("=" * 70)
    print(f"  Victim IP        : {host_ip}")
    print(f"  Interface        : {iface or 'auto (Scapy default)'}")
    print(f"  Firewall backend : {fw_backend}")
    print(f"  Admin dashboard  : {Config.INSPECTOR_IP}:{Config.INSPECTOR_PORT}"
          f"{Config.INSPECTOR_PATH}")
    print(f"  Time window      : {Config.TIME_WINDOW}s")
    print(f"  Learning phase   : {Config.LEARNING_WINDOWS} windows "
          f"({learn_secs}s)  ← NO alerts fire during this phase")
    print(f"  Alert threshold  : mean + {Config.SENSITIVITY}sigma  "
          f"(computed from observed traffic, not fixed numbers)")
    print(f"  Confirmation     : {Config.CONFIRM_WINDOWS} consecutive "
          f"anomalous windows before block")
    print(f"  Block TTL        : {Config.BLOCK_DURATION}s")
    print(f"  Log file         : {Config.LOG_FILE}")
    print("=" * 70)
    print("  Detects  : TCP SYN Flood | UDP Flood | ICMP Flood | Mixed Flood")
    print("  Blocks   : ✓    Notifies : ✓    Reports to admin dashboard : ✓")
    print(f"\n  *** Observing traffic for {learn_secs}s before arming ***\n")
    print("  [Ctrl+C to stop]\n")

    Logger.log(
        "SYSTEM", host_ip,
        f"Detector started — {platform_str}  "
        f"iface={iface or 'auto'}  "
        f"admin={Config.INSPECTOR_IP}  "
        f"learn={Config.LEARNING_WINDOWS}w  "
        f"sensitivity={Config.SENSITIVITY}sigma  "
        f"confirm={Config.CONFIRM_WINDOWS}w"
    )

    global _fw_ref
    firewall  = FirewallManager()
    _fw_ref   = firewall              # expose to shutdown / atexit handler
    atexit.register(_cleanup_on_exit) # safety net for any sys.exit() path
    inspector = InspectorClient(host_ip)
    detector  = DDoSDetector(host_ip, firewall, inspector)

    print(f"[*] Sniffing on '{iface or 'default'}' …\n")

    sniff(
        iface  = iface,
        prn    = detector.process,
        store  = False,
        filter = "ip",
    )


if __name__ == "__main__":
    main()
