"""
detector.py  –  DDoS Detection Engine for NetShield IDS/IPS (Windows Edition)
==============================================================================

DETECTION SIGNALS (all independent — a mixed-protocol flood fires all that apply)
──────────────────────────────────────────────────────────────────────────────────
1. TCP SYN Flood      — absolute count  + adaptive threshold + SYN-ratio guard
2. UDP Flood          — absolute count  + adaptive threshold + spike detection
3. ICMP Echo Flood    — absolute count  + adaptive threshold + spike detection
4. ICMP Smurf Attack  — destination-based ICMP-reply counter (victim side)
5. High-Rate Flood    — catches mixed-protocol floods where no single protocol
                        hits its individual floor

ADAPTIVE THRESHOLD — leave-one-out baseline (key improvement)
──────────────────────────────────────────────────────────────
Old:  baseline = total_packets / num_ips
      Problem: the attacker's own traffic inflates baseline → raises the
               detection bar → delays alerts.

Fixed (leave-one-out):
      other_total  = total_packets - this_ip_count
      other_ips    = num_ips - 1
      baseline     = other_total / other_ips   (0 if only one IP)
      adaptive_thr = baseline * THRESHOLD_MULTIPLIER

The IP under test does NOT influence its own threshold.

SPIKE DETECTION
───────────────
Compares current window count vs. previous window count for each metric.
If current > previous * SPIKE_MULTIPLIER, the metric is flagged as a spike
even if it is below the absolute floor. Catches ramp-up attacks early.

FIREBASE LOGGING
────────────────
Every confirmed attack pushes a structured record to Firebase Realtime DB.
The push runs in a daemon thread so a slow/unavailable Firebase never
blocks packet counting. If firebase_admin is not installed, the push fails
silently — local logging is always preserved.

THREAD MODEL
────────────
• process()            → Scapy sniff() thread — holds lock only for counter updates
• _evaluation_loop()   → daemon background thread, wakes every TIME_WINDOW seconds
• _push_to_firebase()  → one-shot daemon thread per alert
"""

import time
import threading
from collections import defaultdict
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP

from firewall import FirewallManager
from logger   import Logger
from config   import Config


# ── Optional Firebase ─────────────────────────────────────────────
try:
    import firebase_admin
    from firebase_admin import credentials, db as firebase_db
    _FIREBASE_AVAILABLE = True
except ImportError:
    _FIREBASE_AVAILABLE = False

_firebase_ready = False
_firebase_lock  = threading.Lock()


def _init_firebase() -> bool:
    """
    Initialise Firebase Admin SDK once (thread-safe, lazy).
    Returns True on success, False if unavailable or misconfigured.
    """
    global _firebase_ready
    with _firebase_lock:
        if _firebase_ready:
            return True
        if not _FIREBASE_AVAILABLE:
            return False
        if firebase_admin._apps:
            _firebase_ready = True
            return True
        try:
            cert = getattr(
                Config, "FIREBASE_CERT_PATH",
                "firebase-key.json"
            )
            url = getattr(
                Config, "FIREBASE_DB_URL",
                "https://your-firebase-db.firebaseio.com/"
            )
            firebase_admin.initialize_app(
                credentials.Certificate(cert),
                {"databaseURL": url}
            )
            _firebase_ready = True
            return True
        except Exception as exc:
            Logger.log_event(
                "SYSTEM", "0.0.0.0",
                f"[Firebase] Init failed: {exc} — cloud logging disabled."
            )
            return False


class DDoSDetector:
    """
    Stateful per-IP DDoS detector.

    Usage (drop-in replacement for the original):
        det = DDoSDetector(host_ip, firewall)
        # in Scapy sniff callback:
        det.process(pkt)
    """

    def __init__(self, host_ip: str, firewall: FirewallManager):
        self.host_ip  = host_ip
        self.firewall = firewall

        # ── Current-window per-source counters ────────────────────
        # Keys per IP: syn, udp, icmp_req, total
        self._counters: dict = defaultdict(
            lambda: {"syn": 0, "udp": 0, "icmp_req": 0, "total": 0}
        )

        # ── Previous-window snapshot (spike detection) ────────────
        self._prev_counters: dict[str, dict] = {}

        # ── Smurf victim counters (destination-based) ─────────────
        # Maps destination IP → count of ICMP echo-replies received.
        # A victim accumulates replies because its IP was spoofed as the
        # source in broadcast echo-requests.
        self._smurf_victims: dict  = defaultdict(int)
        self._prev_smurf:    dict  = {}

        self._lock = threading.Lock()

        # Start background evaluation thread
        t = threading.Thread(target=self._evaluation_loop, daemon=True)
        t.start()

    # ──────────────────────────────────────────────────────
    #  Packet ingestion
    # ──────────────────────────────────────────────────────

    # ── Trusted public IP prefixes — never count or block ─────────
    # Only well-known public DNS resolvers are whitelisted.
    # LAN/private IPs (192.168.x, 10.x, 172.16.x) are intentionally
    # NOT excluded — the attacker (Kali) is a LAN IP and must be caught.
    _PUBLIC_WHITELIST: tuple = (
        "8.8.",      # Google Public DNS
        "8.8.4.",
        "1.1.1.",    # Cloudflare DNS
        "1.0.0.",
        "9.9.9.",    # Quad9 DNS
    )

    @classmethod
    def _is_whitelisted(cls, ip: str) -> bool:
        """True if ip is a known-safe public infrastructure address."""
        return any(ip.startswith(pfx) for pfx in cls._PUBLIC_WHITELIST)

    def process(self, pkt) -> None:
        """
        Classify and count one IP packet.
        Called from Scapy's sniff() — must be fast.
        Holds the lock only for the dict updates.

        Bridged IDS mode: this host sees all LAN traffic including
        VM-to-VM flows (Kali → Ubuntu). Every source IP except our
        own host and known-safe public resolvers is counted.
        """
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        # Skip our own outbound packets
        if src in (self.host_ip, "127.0.0.1"):
            return

        # Skip known-safe public DNS resolvers.
        # Do NOT add private/LAN ranges here — the attacker IS a LAN IP.
        if self._is_whitelisted(src):
            return

        if self.firewall.is_blocked(src):
            return

        with self._lock:
            c = self._counters[src]
            c["total"] += 1

            if pkt.haslayer(TCP):
                if pkt[TCP].flags & 0x02:      # SYN flag
                    c["syn"] += 1

            elif pkt.haslayer(UDP):
                c["udp"] += 1

            elif pkt.haslayer(ICMP):
                icmp_type = pkt[ICMP].type

                if icmp_type == 8:
                    # Echo-request: count against the sender
                    c["icmp_req"] += 1

                elif icmp_type == 0:
                    # Echo-reply arriving at dst: potential Smurf victim.
                    # In a Smurf attack the victim receives replies because
                    # its IP was spoofed as the source of broadcast probes.
                    self._smurf_victims[dst] += 1

    # ──────────────────────────────────────────────────────
    #  Evaluation loop
    # ──────────────────────────────────────────────────────

    def _evaluation_loop(self) -> None:
        """Wake every TIME_WINDOW seconds and evaluate the snapshot."""
        while True:
            time.sleep(Config.TIME_WINDOW)
            self._evaluate()

    def _evaluate(self) -> None:
        """
        Atomically snapshot + clear counters, then run all checks.
        The lock is held only for the snapshot so detection work
        (string formatting, Firebase) never blocks packet counting.
        """
        with self._lock:
            snapshot = {ip: dict(c) for ip, c in self._counters.items()}
            smurf_snap = dict(self._smurf_victims)
            self._counters.clear()
            self._smurf_victims.clear()

        if not snapshot and not smurf_snap:
            return

        # Global packet stats (used for leave-one-out adaptive threshold)
        total_packets = sum(c["total"] for c in snapshot.values())
        num_ips       = len(snapshot)

        # Per-source-IP checks
        for src_ip, counts in snapshot.items():
            # ── Leave-one-out adaptive threshold ──────────────────
            # Exclude this IP's own traffic when computing the baseline
            # so the attacker cannot inflate the threshold against itself.
            other_total  = total_packets - counts["total"]
            other_ips    = num_ips - 1
            baseline     = (other_total / other_ips) if other_ips > 0 else 0
            adaptive_thr = baseline * Config.THRESHOLD_MULTIPLIER

            prev = self._prev_counters.get(src_ip, {})
            self._check_ip(src_ip, counts, adaptive_thr, prev)

        # Smurf victim checks
        for victim_ip, reply_count in smurf_snap.items():
            prev_replies = self._prev_smurf.get(victim_ip, 0)
            self._check_smurf(victim_ip, reply_count, prev_replies)

        # Store this window as previous for the next window
        self._prev_counters = snapshot
        self._prev_smurf    = smurf_snap

    # ──────────────────────────────────────────────────────
    #  Per-IP checks  (Signals 1, 2, 3, 5)
    # ──────────────────────────────────────────────────────

    def _check_ip(
        self,
        src_ip:       str,
        counts:       dict,
        adaptive_thr: float,
        prev:         dict,
    ) -> None:
        """
        Run all protocol checks for one source IP.
        Every check is independent — a mixed-protocol flood fires
        every applicable attack type, not just the first one matched.

        Parameters
        ----------
        src_ip       : source IP under test
        counts       : current window {syn, udp, icmp_req, total}
        adaptive_thr : leave-one-out adaptive threshold for this IP
        prev         : previous window counts (empty dict if first window)
        """
        if counts["total"] < Config.MIN_PACKETS_TO_ALERT:
            return

        total       = counts["total"]
        spike_mult  = getattr(Config, "SPIKE_MULTIPLIER", 5.0)

        # ── Inline helpers ─────────────────────────────────────────

        def over_threshold(val: int, floor: int) -> bool:
            """
            True if val exceeds the static floor OR the adaptive threshold.
            OR logic is intentional: with only one active IP the adaptive
            threshold collapses to 0 (no other IPs to baseline against).
            Using AND would gate on adaptive_thr=0 and silently miss attacks
            when only one source IP is seen in the window (e.g. solo UDP flood
            from Kali when no other LAN traffic exists at that moment).
            The floor alone is sufficient as the hard minimum; adaptive adds
            sensitivity against low-and-slow floods on busy networks.
            """
            return val > floor or (adaptive_thr > 0 and val > adaptive_thr)

        def is_spike(key: str) -> bool:
            """
            True if the current value is spike_mult× larger than the previous
            window value.  Requires at least one previous window so we do not
            false-positive on the very first burst of traffic at startup.
            """
            prev_val = prev.get(key, 0)
            if prev_val == 0:
                return False
            return counts[key] > prev_val * spike_mult

        # ── SYN ratio ─────────────────────────────────────────────
        # Fraction of packets from this IP that are SYN-only.
        # A legitimate host rarely has 80%+ SYN ratio; a flooder often does.
        syn_ratio           = counts["syn"] / total if total > 0 else 0
        syn_ratio_threshold = getattr(Config, "SYN_RATIO_THRESHOLD", 0.80)

        # ── Signal 1: TCP SYN Flood ────────────────────────────────
        syn_hit = (
            over_threshold(counts["syn"], Config.SYN_FLOOR)     # absolute + adaptive
            or is_spike("syn")                                   # sudden spike
            or (                                                 # ratio guard
                syn_ratio >= syn_ratio_threshold
                and counts["syn"] > Config.SYN_FLOOR // 2       # at least half the floor
            )
        )
        if syn_hit:
            self._fire(
                "TCP SYN FLOOD", src_ip, counts,
                f"SYN={counts['syn']} ratio={syn_ratio:.0%} "
                f"adaptive_thr={adaptive_thr:.0f} prev_syn={prev.get('syn',0)}"
            )

        # ── Signal 2: UDP Flood ────────────────────────────────────
        udp_hit = over_threshold(counts["udp"], Config.UDP_FLOOR) or is_spike("udp")
        if udp_hit:
            self._fire(
                "UDP FLOOD", src_ip, counts,
                f"UDP={counts['udp']} "
                f"adaptive_thr={adaptive_thr:.0f} prev_udp={prev.get('udp',0)}"
            )

        # ── Signal 3: ICMP Echo-Request Flood ─────────────────────
        icmp_hit = (
            over_threshold(counts["icmp_req"], Config.ICMP_FLOOR)
            or is_spike("icmp_req")
        )
        if icmp_hit:
            self._fire(
                "ICMP FLOOD", src_ip, counts,
                f"ICMP_REQ={counts['icmp_req']} "
                f"adaptive_thr={adaptive_thr:.0f} prev_icmp={prev.get('icmp_req',0)}"
            )

        # ── Signal 5: Generic High-Rate Flood (mixed protocol) ─────
        # Only fires when no single-protocol check already fired.
        # Catches tools that spread traffic across all protocols to
        # stay under individual floors.
        #
        # CRITICAL GUARD: require at least one attack-protocol packet.
        # Pure TCP ACK/data/response traffic has SYN=0 UDP=0 ICMP=0.
        # Without this guard, any server (CDN, DNS) that sends a burst
        # of TCP data responses gets flagged as a flood attacker.
        # The spike fallback is also gated on TOTAL_FLOOR so a single
        # quiet-window burst from a CDN never trips it.
        already_flagged    = syn_hit or udp_hit or icmp_hit
        attack_proto_count = counts["syn"] + counts["udp"] + counts["icmp_req"]
        has_attack_traffic = attack_proto_count > 0

        generic_hit = (
            not already_flagged
            and has_attack_traffic
            and over_threshold(total, Config.TOTAL_FLOOR)
        )
        if not already_flagged and not generic_hit and has_attack_traffic:
            # Spike fallback — only if total also clears the absolute floor
            generic_hit = total > Config.TOTAL_FLOOR and is_spike("total")

        if generic_hit:
            self._fire(
                "HIGH-RATE FLOOD", src_ip, counts,
                f"TOTAL={total} SYN={counts['syn']} "
                f"UDP={counts['udp']} ICMP={counts['icmp_req']} "
                f"adaptive_thr={adaptive_thr:.0f}"
            )

    # ──────────────────────────────────────────────────────
    #  Smurf check  (Signal 4 — destination-based)
    # ──────────────────────────────────────────────────────

    def _check_smurf(
        self,
        victim_ip:    str,
        reply_count:  int,
        prev_replies: int,
    ) -> None:
        """
        Detect ICMP Smurf amplification by counting echo-replies per destination.

        Smurf attack mechanics:
          1. Attacker sends ICMP echo-requests to a broadcast address,
             spoofing the victim's IP as the source.
          2. Every host on the subnet replies to the victim's IP.
          3. The victim is flooded with echo-replies (ICMP type=0).

        We count incoming type=0 packets per destination.  A legitimate
        host receives very few echo-replies in a 5-second window; a Smurf
        victim receives hundreds.
        """
        smurf_floor = getattr(Config, "SMURF_REPLY_FLOOR", 100)
        spike_mult  = getattr(Config, "SPIKE_MULTIPLIER", 5.0)

        absolute_hit = reply_count > smurf_floor
        spike_hit    = prev_replies > 0 and reply_count > prev_replies * spike_mult

        if not (absolute_hit or spike_hit):
            return

        detail = (
            f"ICMP_REPLIES={reply_count} floor={smurf_floor} prev={prev_replies}"
        )
        # ── ALERT ONLY — no blocking of any kind ─────────────────
        # victim_ip is the DESTINATION being flooded, not the attacker.
        # The attacker's real IP is spoofed behind a broadcast address
        # and cannot be reliably identified from here.
        # Calling _fire() or firewall.block(victim_ip) would cut off
        # a legitimate host. This method MUST NOT do either.
        Logger.log_event(
            "SMURF", victim_ip,
            f"[SMURF ATTACK] {victim_ip} is receiving amplified ICMP replies "
            f"— victim is being flooded, attacker IP is spoofed. {detail}"
        )
        self._push_to_firebase(
            attack_type  = "ICMP SMURF",
            src_ip       = "broadcast/spoofed",   # real attacker not observable
            victim_ip    = victim_ip,
            packet_count = reply_count,
            detail       = detail,
        )
        # SAFETY: do NOT call self._fire() or self.firewall.block() here.
        # victim_ip must never be blocked.

    # ──────────────────────────────────────────────────────
    #  Alert dispatcher
    # ──────────────────────────────────────────────────────

    def _fire(
        self,
        attack_type: str,
        src_ip:      str,
        counts:      dict,
        detail:      str,
    ) -> None:
        """
        Log locally, block via firewall, push to Firebase.
        Called once per confirmed attack type per evaluation window.
        """
        Logger.log_event(
            "DDOS", src_ip,
            f"[{attack_type}] {detail}"
        )

        if not self.firewall.is_blocked(src_ip):
            self.firewall.block(src_ip, reason=attack_type)

        self._push_to_firebase(
            attack_type  = attack_type,
            src_ip       = src_ip,
            victim_ip    = self.host_ip,
            packet_count = counts["total"],
            detail       = detail,
        )

    # ──────────────────────────────────────────────────────
    #  Firebase cloud push  (non-blocking daemon thread)
    # ──────────────────────────────────────────────────────

    def _push_to_firebase(
        self,
        attack_type:  str,
        src_ip:       str,
        victim_ip:    str,
        packet_count: int,
        detail:       str,
    ) -> None:
        """
        Push one attack record to Firebase Realtime Database.

        Runs in a daemon thread so a slow or unavailable Firebase never
        stalls the evaluation loop or packet processing.

        Firebase path:  ddos_alerts/<safe_src_ip>_<timestamp_ms>

        Record structure:
          {
            "timestamp":    "2025-04-19 14:32:01",
            "type":         "DDOS",
            "attack_type":  "TCP SYN FLOOD",
            "source_ip":    "192.168.62.86",
            "victim_ip":    "192.168.62.100",
            "packet_count": 4500,
            "details":      "SYN=4200 ratio=93% adaptive_thr=120 prev_syn=55"
          }
        """
        def _push():
            if not _init_firebase():
                return   # unavailable — warned at init time

            try:
                # Firebase keys must not contain  . / [ ] $ # or spaces
                # Format: YYYY-MM-DD_HH-MM-SS_IP (User-friendly and easily sortable)
                safe_src = src_ip.replace(".", "_").replace("/", "_")
                time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                key      = f"{time_str}_{safe_src}"

                record = {
                    "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type":         "DDOS",
                    "attack_type":  attack_type,
                    "source_ip":    src_ip,
                    "victim_ip":    victim_ip,
                    "packet_count": packet_count,
                    "details":      detail,
                }
                firebase_db.reference("ddos_alerts").child(key).set(record)

            except Exception as exc:
                # Never raise — local logging is already done; cloud is best-effort.
                Logger.log_event(
                    "SYSTEM", "0.0.0.0",
                    f"[Firebase] Push failed for {src_ip}: {exc}"
                )

        threading.Thread(target=_push, daemon=True).start()
