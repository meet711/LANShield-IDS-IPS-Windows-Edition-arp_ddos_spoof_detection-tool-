"""
arp_detection.py  –  ARP Spoofing Detection Engine (Windows Edition)
=====================================================================

HOW ARP SPOOFING ACTUALLY WORKS (and why attribution matters)
──────────────────────────────────────────────────────────────
When Kali runs:
    arpspoof -i eth0 -t <Windows-IP> <Ubuntu-IP>

It sends forged ARP replies to Windows with:
    ARP.psrc  = <Ubuntu-IP>            ← FORGED  (victim's IP)
    ARP.hwsrc = <Kali-MAC>             ← REAL    (attacker's MAC)

So every captured packet says: "I am Ubuntu, my MAC is Kali's MAC."

Naïve detectors read psrc/hwsrc, detect a mismatch on the victim IP,
and then (wrongly) BLOCK the victim.  The attacker keeps running.

CORRECT ATTRIBUTION
───────────────────
When a mismatch fires for (victim_ip, attacker_mac):

    attacker_real_ip  =  _mac_to_ips[attacker_mac]
                         − {victim_ip, host_ip, gateway_ip}

Block attacker_real_ip, NOT victim_ip.

This works because arpspoof emits normal ARP traffic from its own IP
before (and between) sending forged replies, so attacker_mac →
attacker_real_ip is already in _mac_to_ips.

THREE DETECTION SIGNALS (all run on every packet independently)
───────────────────────────────────────────────────────────────
1. IP → MAC mismatch  — victim IP advertised with wrong MAC.
                         Fires after ARP_MISMATCH_THRESHOLD packets.
                         RESETS when victim's real MAC is seen again,
                         so EVERY new attack round is detected fresh.

2. MAC → multiple IPs — one MAC claims ≥ MAC_MULTI_IP_THRESHOLD IPs.
                         RESETS per-IP alert state when attack stops,
                         so a repeated attack re-triggers the alert.

3. Gateway spoof      — gateway IP claimed by any non-baseline MAC.
                         Fires once per (gateway_ip, attacker_mac) pair
                         per attack round; resets when attack stops.

REPEAT-ATTACK DESIGN (the core invariant)
──────────────────────────────────────────
The previous version added attacker MACs to a permanent blacklist
(_confirmed_attacker_macs) and dropped their packets in process().
That broke repeated detection because the blacklist was never cleared.

The fixed design:
  • NO permanent MAC blacklist in process().  Every packet is inspected.
  • The mismatch threshold + _alerted_spoof dict handle ongoing-attack
    suppression (no repeat alerts while attack is active).
  • When the attack stops, real-MAC packets from the victim cause
    _check_ip_mac_mismatch() to RESET the counter and CLEAR alerted_spoof,
    making the detector fully ready for the next attack round.
  • _mac_multi_alerted_at is similarly reset when clean traffic appears.

BASELINE ANTI-POISONING
────────────────────────
• seed_baseline() is called from main.py with ARP scan results collected
  BEFORE sniffing starts — verified ground-truth, immune to live traffic.
• _verified_baseline is write-once per IP after seeding.
• The short learning fallback (3 s) rejects a MAC for a new IP if that
  MAC is already associated with a different IP in the baseline.
"""

import time
import threading
from collections import defaultdict
from scapy.all import ARP


from firewall import FirewallManager
from logger   import Logger
from config   import Config


_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
_SKIP_IPS  = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


class ARPSpoofDetector:
    """
    Stateful ARP-spoofing detector.

    Lifecycle
    ─────────
    1. Construct the object (host_ip, host_mac, gateway_ip, firewall).
    2. Call seed_baseline(ip_mac_dict) with pre-scan results.
    3. Call process(pkt) for every ARP packet from Scapy.
    """

    def __init__(
        self,
        host_ip:    str,
        host_mac:   str,
        gateway_ip: str | None,   # None on host-only networks (no default route)
        firewall:   FirewallManager,
    ):
        self.host_ip    = host_ip
        self.host_mac   = host_mac.lower()
        # None means "no gateway" — Signal 3 (gateway spoof) will be skipped.
        # The old code passed '0.0.0.0' here; that IP is in _SKIP_IPS so the
        # gateway-spoof check was a permanent no-op.  None is explicit and safe.
        self.gateway_ip = gateway_ip
        self.firewall   = firewall

        global firewall_global
        firewall_global = firewall

        # ── Baseline ─────────────────────────────────────────────
        # IP → trusted MAC.  Set by seed_baseline() and NEVER overwritten
        # by live traffic — this is the permanent ground-truth reference.
        self._verified_baseline: dict[str, str] = {}

        # ── Mismatch tracking (Signal 1) ─────────────────────────
        # Consecutive mismatch count per victim IP.
        # Resets to 0 when the victim's real MAC is seen again (attack stops).
        self._mismatch_counter: dict[str, int] = defaultdict(int)

        # victim_ip → attacker_mac for the currently active confirmed attack.
        # Prevents log-spam during an ongoing attack.
        # CLEARED when a clean packet arrives (attack stops) so the next
        # attack round is detected fresh.
        self._alerted_spoof: dict[str, str] = {}

        # ── Multi-IP tracking (Signal 2) ─────────────────────────
        # MAC → set of distinct IPs ever claimed (real or forged).
        self._mac_to_ips: dict[str, set] = defaultdict(set)

        # MAC → count of claimed IPs at the time of the LAST multi-IP alert.
        # Reset per IP pair when attack stops so repeat attacks re-fire.
        self._mac_multi_alerted_at: dict[str, int] = {}

        # ── Gateway spoof tracking (Signal 3) ────────────────────
        # Set of (gateway_ip, attacker_mac) pairs that have already fired
        # an alert in the CURRENT attack round.
        # Cleared when clean gateway traffic is seen (attack stops).
        self._gw_alerted: set = set()

        # ── Learning phase ────────────────────────────────────────
        # Short fallback for IPs not covered by the ARP scan baseline.
        self._learning_start = time.monotonic()
        self._learning_secs  = 3

        self._lock = threading.Lock()

    # ──────────────────────────────────────────────────────
    #  Baseline injection  (call BEFORE sniffing starts)
    # ──────────────────────────────────────────────────────

    def seed_baseline(self, ip_mac_map: dict[str, str]) -> None:
        """
        Load verified IP → MAC mappings from the pre-scan in main.py.
        Must be called before any packet arrives at process().
        """
        if not ip_mac_map:
            Logger.log_event(
                "SYSTEM", "0.0.0.0",
                "ARP baseline is empty — falling back to short learning phase."
            )
            return

        with self._lock:
            for ip, mac in ip_mac_map.items():
                mac = mac.lower()
                if ip in _SKIP_IPS or ip == self.host_ip:
                    continue
                if mac in _NULL_MACS:
                    continue
                self._verified_baseline[ip] = mac
                # Pre-populate mac_to_ips so attacker attribution works
                # from the very first forged packet.
                self._mac_to_ips[mac].add(ip)

        count   = len(self._verified_baseline)
        preview = ", ".join(
            f"{ip}→{mac}"
            for ip, mac in list(self._verified_baseline.items())[:6]
        )
        Logger.log_event(
            "SYSTEM", "0.0.0.0",
            f"Baseline seeded: {count} host(s) — {preview}"
            + (" …" if count > 6 else "")
        )

    # ──────────────────────────────────────────────────────
    #  Public packet ingestion
    # ──────────────────────────────────────────────────────

    def process(self, pkt) -> None:
        """
        Entry point — called by Scapy's sniff() for every ARP frame.

        Design note: there is NO MAC blacklist here.
        Earlier versions dropped packets from "confirmed attacker" MACs,
        which permanently blinded the detector to repeat attacks after
        the firewall auto-unblocked the attacker.  The correct approach
        is to let every packet through and rely on the mismatch counter
        + alert-suppression logic to avoid spam while keeping detection
        active across multiple attack rounds.
        """
        if not pkt.haslayer(ARP):
            return

        arp        = pkt[ARP]
        sender_ip  = arp.psrc.strip()
        sender_mac = arp.hwsrc.strip().lower()

        # Hard filters — skip unroutable/reserved addresses
        if sender_ip in _SKIP_IPS or sender_ip == self.host_ip:
            return
        if sender_mac in _NULL_MACS or sender_mac == self.host_mac:
            return

        with self._lock:
            self._ingest(sender_ip, sender_mac)

    # ──────────────────────────────────────────────────────
    #  Core detection pipeline  (runs under _lock)
    # ──────────────────────────────────────────────────────

    def _ingest(self, ip: str, mac: str) -> None:
        """
        Runs all three signals on every packet.
        Signal 2 (multi-IP) runs first — it is the strongest standalone
        indicator and requires no baseline entry to fire.
        """
        # Always accumulate the MAC → IP mapping
        self._mac_to_ips[mac].add(ip)

        # Signal 2: MAC claiming multiple IPs (runs unconditionally)
        self._check_mac_multi_ip(mac)

        # Baseline population for IPs not yet known
        if ip not in self._verified_baseline:
            self._try_learn(ip, mac)
            return

        # Signal 3: gateway impersonation
        # Skip if gateway_ip is None (host-only network with no gateway).
        if self.gateway_ip and ip == self.gateway_ip:
            self._check_gateway_spoof(ip, mac)
            return

        # Signal 1: IP → MAC mismatch against verified baseline
        self._check_ip_mac_mismatch(ip, mac)

    # ──────────────────────────────────────────────────────
    #  Learning phase helper
    # ──────────────────────────────────────────────────────

    def _try_learn(self, ip: str, mac: str) -> None:
        """
        Add ip → mac to the baseline only within the learning window
        and only if the MAC is not already associated with a different IP
        (which would indicate an active spoofing MAC).
        """
        in_learning = (
            time.monotonic() - self._learning_start
        ) < self._learning_secs

        # Reject if this MAC already owns a different baseline IP
        for known_ip, known_mac in self._verified_baseline.items():
            if known_mac == mac and known_ip != ip:
                Logger.log_event(
                    "ARP_SPOOF", ip,
                    f"[LEARNING BLOCK] Refused to trust {ip}→{mac}: "
                    f"MAC already owns {known_ip} — possible poisoning attempt"
                )
                return

        if in_learning or ip not in self._verified_baseline:
            self._verified_baseline[ip] = mac

    # ──────────────────────────────────────────────────────
    #  Signal 1: IP → MAC mismatch
    # ──────────────────────────────────────────────────────

    def _check_ip_mac_mismatch(self, victim_ip: str, attacker_mac: str) -> None:
        """
        Compare the observed MAC for victim_ip against the verified baseline.

        State transitions
        ─────────────────
        Attack starts  → mismatch_counter[victim_ip] increments each packet.
                         At threshold: CONFIRMED SPOOF alert + block attacker.
                         After alert: _alerted_spoof suppresses further alerts
                         for the same (victim_ip, attacker_mac) pair while
                         the attack is ongoing.

        Attack stops   → victim's real MAC arrives.
                         mismatch_counter[victim_ip] = 0
                         _alerted_spoof[victim_ip]   cleared
                         Detector is now FULLY RESET for this victim IP.

        Attack restarts → counter starts from 0, alert fires again at threshold.
        """
        trusted_mac = self._verified_baseline[victim_ip]

        # ── Clean packet: attack has stopped ──────────────────────
        if attacker_mac == trusted_mac:
            prev_count = self._mismatch_counter.get(victim_ip, 0)
            prev_alert = self._alerted_spoof.pop(victim_ip, None)

            self._mismatch_counter[victim_ip] = 0

            if prev_alert:
                # Inform that the attack on this IP appears to have stopped
                Logger.log_event(
                    "ARP_SPOOF", victim_ip,
                    f"[ATTACK STOPPED] {victim_ip} is back to its legitimate MAC "
                    f"{trusted_mac}. Detector reset — ready for next round."
                )
                # Also reset the multi-IP alert counter for the attacker's MAC
                # so that if the same MAC attacks again, the multi-IP alert fires too.
                if victim_ip in self._mac_to_ips.get(prev_alert, set()):
                    self._mac_multi_alerted_at.pop(prev_alert, None)

            elif prev_count > 0:
                # Partial mismatch sequence that never reached threshold — just reset
                Logger.log_event(
                    "ARP_SPOOF", victim_ip,
                    f"[CLEARED] {victim_ip} mismatch count reset "
                    f"(was {prev_count}, never confirmed)."
                )
            return

        # ── Mismatch: victim IP claimed by wrong MAC ───────────────
        self._mismatch_counter[victim_ip] += 1
        count     = self._mismatch_counter[victim_ip]
        threshold = Config.ARP_MISMATCH_THRESHOLD

        if count < threshold:
            Logger.log_event(
                "ARP_SPOOF", victim_ip,
                f"[SUSPECT] {victim_ip} claimed by {attacker_mac} "
                f"(trusted: {trusted_mac}) — mismatch {count}/{threshold}"
            )
            return

        # Threshold reached — confirmed spoof
        # Suppress duplicate alerts while the same attack is ongoing.
        # Note: _alerted_spoof is cleared when the attack stops (above),
        # so the NEXT attack round will get a fresh alert.
        if self._alerted_spoof.get(victim_ip) == attacker_mac:
            return

        self._alerted_spoof[victim_ip] = attacker_mac

        # ── Identify attacker's real IP ────────────────────────────
        # The attacker's MAC was seen with its own real IP in normal
        # traffic before/during the attack.  Remove all "innocent" IPs
        # (the victim IP it forged, our own IP, the gateway) to isolate
        # the attacker's true address.
        excluded          = {victim_ip, self.host_ip} | ({self.gateway_ip} if self.gateway_ip else set())
        attacker_real_ips = self._mac_to_ips[attacker_mac] - excluded
        attacker_ip_str   = (
            ", ".join(sorted(attacker_real_ips))
            if attacker_real_ips
            else "unknown — awaiting identifying packet"
        )

        Logger.log_event(
            "ARP_SPOOF", victim_ip,
            f"[CONFIRMED SPOOF] {victim_ip} is being hijacked. "
            f"Victim MAC: {trusted_mac} | "
            f"Attacker MAC: {attacker_mac} | "
            f"Attacker real IP: {attacker_ip_str}"
        )

        # Block the ATTACKER's IP, not the victim's IP
        if attacker_real_ips:
            for aip in attacker_real_ips:
                if not self.firewall.is_blocked(aip):
                    self.firewall.block(
                        aip,
                        reason=(
                            f"ARP spoof: impersonated {victim_ip} "
                            f"using MAC {attacker_mac}"
                        )
                    )
        else:
            # Real IP not yet seen.  The multi-IP check will block it
            # as soon as the attacker sends any normal traffic.
            Logger.log_event(
                "ARP_SPOOF", victim_ip,
                f"[PENDING BLOCK] Attacker MAC {attacker_mac} has no known real IP yet. "
                f"Will block automatically on next identifying packet."
            )

    # ──────────────────────────────────────────────────────
    #  Signal 2: MAC → multiple IPs
    # ──────────────────────────────────────────────────────

    def _check_mac_multi_ip(self, mac: str) -> None:
        """
        Fires when one MAC has claimed ≥ MAC_MULTI_IP_THRESHOLD distinct IPs.
        Runs on EVERY packet, independently of Signal 1.

        Repeat-attack behaviour
        ───────────────────────
        _mac_multi_alerted_at[mac] is reset by _check_ip_mac_mismatch()
        when a clean packet arrives (attack stops).  This means the
        multi-IP alert fires again at the start of the next attack round
        even though the same IP set is being claimed.
        """
        claimed   = self._mac_to_ips[mac]
        threshold = getattr(Config, "MAC_MULTI_IP_THRESHOLD", 2)

        if len(claimed) < threshold:
            return

        # Fire again only when the IP set has grown since the last alert,
        # OR when _mac_multi_alerted_at was reset by the stop-detection path.
        last_alerted = self._mac_multi_alerted_at.get(mac, 0)
        if len(claimed) <= last_alerted:
            return

        self._mac_multi_alerted_at[mac] = len(claimed)

        # Identify attacker's legitimate IP (the one in the baseline for this MAC)
        legitimate_ip = self._baseline_ip_for_mac(mac)
        forged_ips    = claimed - ({legitimate_ip} if legitimate_ip else set())

        Logger.log_event(
            "ARP_SPOOF", mac,
            f"[CULPRIT IDENTIFIED] MAC {mac} claims {len(claimed)} IPs: "
            f"[{', '.join(sorted(claimed))}]. "
            f"Real IP: {legitimate_ip or 'unknown'} | "
            f"Forged IPs: [{', '.join(sorted(forged_ips))}]"
        )

        # Block the attacker's real IP only
        if legitimate_ip and not self.firewall.is_blocked(legitimate_ip):
            self.firewall.block(
                legitimate_ip,
                reason=f"Multi-IP spoof: MAC {mac} claiming {len(claimed)} IPs"
            )

    # ──────────────────────────────────────────────────────
    #  Signal 3: Gateway impersonation
    # ──────────────────────────────────────────────────────

    def _check_gateway_spoof(self, gateway_ip: str, attacker_mac: str) -> None:
        """
        Any packet claiming the gateway IP with a non-baseline MAC is critical.
        The verified baseline is NEVER updated — the legitimate gateway MAC
        stays pinned permanently.

        Repeat-attack behaviour
        ───────────────────────
        _gw_alerted is a set of (gateway_ip, attacker_mac) pairs that fired
        in the current attack round.  When the attack stops, clean gateway
        traffic causes this entry to be removed (see clean-packet path below),
        so the alert fires again when the attack restarts.
        """
        trusted_mac = self._verified_baseline[gateway_ip]

        if attacker_mac == trusted_mac:
            # Clean gateway packet — remove any active alert suppressor
            # so a future attack on the gateway re-fires.
            alert_key = (gateway_ip, attacker_mac)
            self._gw_alerted.discard(alert_key)
            return

        alert_key = (gateway_ip, attacker_mac)
        if alert_key in self._gw_alerted:
            return   # suppress spam during ongoing attack

        self._gw_alerted.add(alert_key)

        # Find attacker's real IP
        excluded          = {gateway_ip, self.host_ip}
        attacker_real_ips = self._mac_to_ips[attacker_mac] - excluded
        attacker_ip_str   = (
            ", ".join(sorted(attacker_real_ips)) if attacker_real_ips else "unknown"
        )

        Logger.log_event(
            "ARP_SPOOF", gateway_ip,
            f"[CRITICAL — GATEWAY SPOOF] Gateway {gateway_ip} is being impersonated! "
            f"Trusted MAC: {trusted_mac} | "
            f"Attacker MAC: {attacker_mac} | "
            f"Attacker real IP: {attacker_ip_str}"
        )

        for aip in attacker_real_ips:
            if not self.firewall.is_blocked(aip):
                self.firewall.block(
                    aip,
                    reason=f"Gateway spoof of {gateway_ip} via MAC {attacker_mac}"
                )

    # ──────────────────────────────────────────────────────
    #  Helper
    # ──────────────────────────────────────────────────────

    def _baseline_ip_for_mac(self, mac: str) -> str | None:
        """
        Return the IP legitimately associated with this MAC in the verified
        baseline (i.e. the attacker's real IP before it started spoofing).
        Returns None if the MAC was not in the baseline.
        """
        for ip, m in self._verified_baseline.items():
            if m == mac:
                return ip
        return None

    # ──────────────────────────────────────────────────────
    #  Introspection — used by dashboard
    # ──────────────────────────────────────────────────────

    def get_baseline_snapshot(self) -> dict:
        with self._lock:
            return dict(self._verified_baseline)

    def get_mac_to_ips_snapshot(self) -> dict:
        with self._lock:
            return {mac: sorted(ips) for mac, ips in self._mac_to_ips.items()}

    def get_active_alerts(self) -> list:
        """Return currently confirmed ongoing spoof sessions."""
        with self._lock:
            return [
                {"victim_ip": vip, "attacker_mac": amac}
                for vip, amac in self._alerted_spoof.items()
            ]
    # at exit — delegate to the proper public API (unblock_all handles
    # both Windows Firewall rules and Firebase in one place)
    import atexit

    def cleanup():
        global firewall_global
        if firewall_global is not None:
            firewall_global.unblock_all()

    atexit.register(cleanup)
        