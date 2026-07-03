class Config:
    # ── DDoS detection ───────────────────────────────────────────
    TIME_WINDOW          = 5
    THRESHOLD_MULTIPLIER = 3.0
    MIN_PACKETS_TO_ALERT = 50

    SPIKE_MULTIPLIER     = 5.0   # current window must be 5× previous to trigger spike
    SYN_RATIO_THRESHOLD  = 0.80  # 80%+ SYN packets → SYN flood signal
    SMURF_REPLY_FLOOR    = 100   # ICMP replies/window to a single victim before Smurf alert
    FIREBASE_CERT_PATH   = "firebase-key.json"
    FIREBASE_DB_URL      = "https://arp-ddos-idps-default-rtdb.firebaseio.com/"

    SYN_FLOOR   = 100
    UDP_FLOOR   = 200
    ICMP_FLOOR  = 150
    TOTAL_FLOOR = 300

    # ── ARP spoof detection ───────────────────────────────────────

    # Number of IP→MAC mismatches before a confirmed-spoof alert fires.
    # Lower = more sensitive, higher = fewer false positives.
    ARP_MISMATCH_THRESHOLD = 3

    # Number of distinct IPs a single MAC must claim before the
    # MAC→multi-IP alert fires.  2 means: as soon as one MAC
    # appears with two different IPs, alert immediately.
    MAC_MULTI_IP_THRESHOLD = 2

    # ── Blocking ──────────────────────────────────────────────────
    BLOCK_DURATION = 60     # seconds before auto-unblock
    LOG_FILE       = "attacks.log"

    # ── Dashboard ─────────────────────────────────────────────────
    ENABLE_DASHBOARD = True
    DASHBOARD_PORT   = 5000

    # ── Firewall rule naming ──────────────────────────────────────
    FW_RULE_PREFIX = "NETSHIELD_BLOCK_"
