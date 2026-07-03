"""
logger.py  –  Unified logging for NetShield IDS/IPS (Windows Edition)
======================================================================
Writes colour-coded lines to the terminal (via colorama on Windows)
and to a persistent log file.  Also maintains an in-memory event list
for the Flask dashboard.

Windows NOTE:
  ANSI colour codes do NOT work in cmd.exe / PowerShell by default.
  We use the 'colorama' library which wraps Windows Console API calls.
  Install:  pip install colorama
"""

import threading
from datetime import datetime
from config import Config

# ── Colour support on Windows ────────────────────────────────────
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)   # enables ANSI on Windows console
    _COLOUR_MAP = {
        "ARP_SPOOF": Fore.RED    + Style.BRIGHT,
        "DDOS":      Fore.YELLOW + Style.BRIGHT,
        "SMURF":     Fore.MAGENTA + Style.BRIGHT,
        "BLOCK":     Fore.CYAN   + Style.BRIGHT,
        "UNBLOCK":   Fore.GREEN  + Style.BRIGHT,
        "SYSTEM":    Fore.WHITE  + Style.BRIGHT,
    }
    _RESET = Style.RESET_ALL
except ImportError:
    # Graceful fallback: no colour, but fully functional
    _COLOUR_MAP = {}
    _RESET = ""

# ── Shared in-memory store (read by Flask dashboard) ─────────────
_events: list[dict] = []
_events_lock = threading.Lock()


class Logger:
    """Static helper – no instance needed."""

    @staticmethod
    def log_event(event_type: str, src_ip: str, message: str) -> None:
        """
        Log a security event to terminal, file, and in-memory store.

        Parameters
        ----------
        event_type : ARP_SPOOF | DDOS | SMURF | BLOCK | UNBLOCK | SYSTEM
        src_ip     : Source IP (use '0.0.0.0' for system-level events)
        message    : Human-readable description
        """
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{event_type}] SRC={src_ip} | {message}"

        # ── Terminal output (with colour on Windows via colorama) ────
        colour = _COLOUR_MAP.get(event_type, "")
        print(f"{colour}{line}{_RESET}")

        # ── Persistent log file ──────────────────────────────────────
        try:
            with open(Config.LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as e:
            print(f"[Logger ERROR] Cannot write log: {e}")

        # ── In-memory store for dashboard ────────────────────────────
        record = {
            "timestamp":  ts,
            "event_type": event_type,
            "src_ip":     src_ip,
            "message":    message,
        }
        with _events_lock:
            _events.append(record)
            if len(_events) > 200:   # cap memory usage
                _events.pop(0)


def get_recent_events(n: int = 50) -> list[dict]:
    """Return the N most-recent events (thread-safe, used by dashboard)."""
    with _events_lock:
        return list(_events[-n:])
