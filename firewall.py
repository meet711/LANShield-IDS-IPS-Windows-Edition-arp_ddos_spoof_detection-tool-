"""
firewall.py  –  Windows Firewall automation for NetShield IDS/IPS
==================================================================
Uses 'netsh advfirewall' (built into every Windows version since Vista)
to add and remove inbound DROP rules – the Windows equivalent of
Linux iptables.

LINUX → WINDOWS MAPPING
────────────────────────
  iptables -I INPUT -s <ip> -j DROP
  ↕
  netsh advfirewall firewall add rule
        name="NETSHIELD_BLOCK_<ip>"
        dir=in action=block remoteip=<ip>

  iptables -D INPUT -s <ip> -j DROP
  ↕
  netsh advfirewall firewall delete rule
        name="NETSHIELD_BLOCK_<ip>"

REQUIREMENTS
────────────
  • Run the script as Administrator (right-click → Run as administrator,
    or open an elevated PowerShell/cmd and run: python main.py)
  • No third-party tools needed – netsh is built into Windows.
"""

import subprocess
import threading
from datetime import datetime

from logger import Logger
from config import Config

# ── Shared state (read by Flask dashboard) ────────────────────────
_blocked: dict[str, str] = {}   # ip → blocked-at timestamp
_blocked_lock = threading.Lock()


class FirewallManager:
    """
    Windows Firewall wrapper using netsh advfirewall.
    All public methods are thread-safe.
    """

    def __init__(self):
        """Verify netsh is accessible and we have admin rights."""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True, text=True, check=True
            )
            if "ERROR" in result.stdout.upper():
                raise PermissionError
        except (FileNotFoundError, subprocess.CalledProcessError, PermissionError):
            print(
                "[FirewallManager] WARNING: netsh not accessible or insufficient "
                "privileges.\n"
                "  → Run the script as Administrator for firewall blocking to work.\n"
                "  → Detection and logging will still function normally."
            )

    # ─────────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────────

    def block(self, ip: str, reason: str = "") -> None:
        """
        Block all inbound traffic from *ip* via Windows Firewall.
        Schedules automatic unblock after Config.BLOCK_DURATION seconds.
        """
        with _blocked_lock:
            if ip in _blocked:
                return   # already blocked
            _blocked[ip] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._fw_block(ip)

        from firebase_client import push_block
        try:
            push_block(ip, reason)
        except Exception as e:
            print(f"[FirewallManager] Failed to push block to Firebase: {e}")

        Logger.log_event(
            "BLOCK", ip,
            f"Blocked via Windows Firewall (netsh). Reason: {reason}. "
            f"Auto-unblock in {Config.BLOCK_DURATION}s"
        )

        # Schedule auto-unblock
        timer = threading.Timer(Config.BLOCK_DURATION, self._auto_unblock, args=(ip,))
        timer.daemon = True
        timer.start()

    def unblock(self, ip: str) -> None:
        """Manually remove the Windows Firewall rule for *ip*."""
        with _blocked_lock:
            if ip not in _blocked:
                return
            del _blocked[ip]
        self._fw_unblock(ip)
        
        from firebase_client import remove_block
        try:
            remove_block(ip)
        except Exception as e:
            print(f"[FirewallManager] Failed to remove block from Firebase: {e}")
            
        Logger.log_event("UNBLOCK", ip, "IP unblocked (manual)")

    def is_blocked(self, ip: str) -> bool:
        with _blocked_lock:
            return ip in _blocked

    def get_blocked_ips(self) -> dict[str, str]:
        with _blocked_lock:
            return dict(_blocked)

    def unblock_all(self) -> None:
        """Unblock every currently-blocked IP – call this on program exit."""
        with _blocked_lock:
            ips_to_unblock = list(_blocked.keys())

        if not ips_to_unblock:
            return

        print(f"[FirewallManager] Cleaning up {len(ips_to_unblock)} blocked IP(s) on exit …")
        for ip in ips_to_unblock:
            # Remove from Windows Firewall
            self._fw_unblock(ip)

            # Remove from Firebase
            from firebase_client import remove_block
            try:
                remove_block(ip)
            except Exception as e:
                print(f"[FirewallManager] Failed to remove Firebase block for {ip}: {e}")

            Logger.log_event("UNBLOCK", ip, "Unblocked on program exit")

        # Clear the in-memory set
        with _blocked_lock:
            _blocked.clear()

        print("[FirewallManager] All firewall rules cleaned up.")

    # ─────────────────────────────────────────────
    #  Private helpers
    # ─────────────────────────────────────────────

    def _auto_unblock(self, ip: str) -> None:
        with _blocked_lock:
            if ip not in _blocked:
                return   # already manually unblocked
            del _blocked[ip]
        self._fw_unblock(ip)
        
        from firebase_client import remove_block
        try:
            remove_block(ip)
        except Exception as e:
            print(f"[FirewallManager] Failed to remove block from Firebase: {e}")
            
        Logger.log_event("UNBLOCK", ip, f"Auto-unblocked after {Config.BLOCK_DURATION}s")

    @staticmethod
    def _rule_name(ip: str) -> str:
        """Return the Windows Firewall rule name for a given IP."""
        # Replace dots with underscores so the rule name is valid
        return f"{Config.FW_RULE_PREFIX}{ip.replace('.', '_')}"

    @classmethod
    def _fw_block(cls, ip: str) -> None:
        """
        Add a Windows Firewall inbound BLOCK rule for *ip*.

        Equivalent Linux command:
            iptables -I INPUT -s <ip> -j DROP
        """
        rule = cls._rule_name(ip)
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            "profile=any",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"[FirewallManager] netsh BLOCK failed for {ip}: {e.stderr.strip()}")

    @classmethod
    def _fw_unblock(cls, ip: str) -> None:
        """
        Remove the Windows Firewall inbound BLOCK rule for *ip*.

        Equivalent Linux command:
            iptables -D INPUT -s <ip> -j DROP
        """
        rule = cls._rule_name(ip)
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule}",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            pass   # rule may already be gone – fine
