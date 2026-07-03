import time
from firebase_client import get_blocked_ips
from firewall import FirewallManager

fw = FirewallManager()

while True:
    blocked = get_blocked_ips()
    for raw_ip in blocked:
        # Firebase keys use underscores; convert back to standard IP notation
        ip = raw_ip.replace('_', '.')
        
        # We also want to skip metadata or malformed entries
        if '.' not in ip:
            continue
            
        if not fw.is_blocked(ip):
            fw.block(ip, reason="Synced from Firebase")
    time.sleep(5)