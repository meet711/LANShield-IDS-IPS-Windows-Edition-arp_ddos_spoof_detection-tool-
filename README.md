# 🛡 NetShield IDS/IPS — Windows Edition
### Real-Time ARP Spoofing, DDoS & Smurf Detection with Automated Mitigation

---

## ⚙️ What Changed from the Linux Version

| Feature | Linux Version | Windows Edition |
|---|---|---|
| Packet capture | libpcap (built-in) | **Npcap** (must install) |
| Firewall blocking | `iptables` | **`netsh advfirewall`** |
| Interface names | `eth0`, `enp0s3` | `\Device\NPF_{GUID}` (auto-resolved) |
| Admin check | `os.geteuid() == 0` | `ctypes.windll.shell32.IsUserAnAdmin()` |
| Colour output | ANSI codes (native) | **colorama** library |
| New detection | – | **ICMP Smurf attack** added |

---

## 📁 Project Files

```
netshield_windows/
├── main.py            ← Entry point (Windows-aware, auto-detects interface)
├── config.py          ← All tuneable parameters
├── detector.py        ← DDoS + Smurf detection (adaptive threshold)
├── arp_detection.py   ← ARP spoofing detection (IP→MAC table)
├── firewall.py        ← Windows Firewall automation (netsh)
├── logger.py          ← Terminal + file + in-memory logging (colorama)
├── dashboard.py       ← Flask web dashboard
├── requirements.txt   ← Python dependencies
└── attacks.log        ← Auto-created at runtime
```

---

## 📦 Step-by-Step Setup

### Step 1 — Install Npcap (MANDATORY)

Npcap is the Windows equivalent of libpcap. Scapy cannot capture
packets on Windows without it.

1. Download from: **https://npcap.com/#download**
2. Run the installer
3. ✅ CHECK **"WinPcap API-compatible Mode"** during install
4. Reboot if prompted

> **Do NOT use the old WinPcap** – it is unmaintained and broken on Windows 10/11.

---

### Step 2 — Install Python (if not already installed)

Download from https://python.org/downloads  
During install: ✅ CHECK **"Add Python to PATH"**

Verify:
```cmd
python --version
```

---

### Step 3 — Install Python Dependencies

Open **PowerShell or cmd** (does NOT need to be elevated for this step):

```cmd
cd path\to\netshield_windows
pip install -r requirements.txt
```

This installs: `scapy`, `flask`, `colorama`

---

### Step 4 — Run as Administrator

**Method A – Elevated PowerShell (recommended):**
```powershell
# Right-click PowerShell → "Run as Administrator"
cd C:\path\to\netshield_windows
python main.py
```

**Method B – Right-click the script:**
```
Right-click main.py → "Run as Administrator"
(only works if you have Python associated with .py files)
```

---

### Step 5 — Configure Firebase Realtime Database (Optional)

NetShield supports optional cloud integration to sync blocked IP lists in real-time. If you do not configure this, the IDS/IPS will run perfectly with local-only mitigation.

To enable Firebase syncing:
1. Create a Firebase project at the [Firebase Console](https://console.firebase.google.com/).
2. Create a **Realtime Database** and copy its URL (e.g., `https://your-project-id.firebaseio.com/`).
3. Go to **Project Settings** → **Service Accounts**, click **Generate new private key**, and download the JSON file.
4. Save the downloaded JSON file in the project's root directory as `firebase-key.json` (this file is ignored by Git, keeping your credentials secure).
5. Open `config.py` and set `FIREBASE_DB_URL` to match your database URL:
   ```python
   FIREBASE_DB_URL = "https://your-project-id-default-rtdb.firebaseio.com/"
   ```

---

## ▶️ Expected Startup Output

```
=================================================================
     NetShield IDS/IPS  –  Real-Time Protection (Windows)
=================================================================
  Host IP       : 192.168.1.50
  Interface     : Intel(R) Wi-Fi 6 AX200 160MHz
  Time Window   : 5s
  Thr Multiplier: 3.0x
  Block TTL     : 60s
  Log file      : attacks.log
=================================================================

  Available network interfaces:
  #    IP Address         Description
  ---- ------------------ ----------------------------------------
  0    192.168.1.50       Intel(R) Wi-Fi 6 AX200 160MHz
  1    192.168.56.1       VirtualBox Host-Only Ethernet Adapter
  2    0.0.0.0            WAN Miniport (IP)

  Detects: TCP SYN Flood | UDP Flood | ICMP Flood | ICMP Smurf | ARP Spoofing
  Blocks via: Windows Firewall (netsh advfirewall)
  [Ctrl+C to stop]

[*] Dashboard → http://127.0.0.1:5000
[*] Sniffing on Intel(R) Wi-Fi 6 AX200 160MHz ...
```

---

## 🧪 Attack Simulation from Kali Linux

> Ubuntu VM's IP = `192.168.1.50` (Windows host IP)

### TCP SYN Flood
```bash
sudo hping3 --flood --syn -p 80 192.168.1.50
```

### UDP Flood
```bash
sudo hping3 --flood --udp -p 80 192.168.1.50
```

### ICMP Flood
```bash
sudo hping3 --flood --icmp 192.168.1.50
```

### ICMP Smurf Attack
```bash
# Find your broadcast address first:
ip route   # look for broadcast address, e.g. 192.168.1.255

# Spoof the victim's IP as source, flood the broadcast address:
sudo hping3 --icmp -a 192.168.1.50 --flood 192.168.1.255
```
The broadcast address replies to the spoofed source (victim), causing
a flood of ICMP echo replies at 192.168.1.50 — NetShield detects this
via the `icmp_rep` (echo-reply) counter.

### ARP Spoofing
```bash
sudo python3 arp_attack.py
```

---

## 🔥 How Windows Firewall Blocking Works

When an attack is confirmed, NetShield runs:

```python
# Equivalent to: iptables -I INPUT -s <ip> -j DROP
subprocess.run([
    "netsh", "advfirewall", "firewall", "add", "rule",
    "name=NETSHIELD_BLOCK_192_168_1_100",
    "dir=in", "action=block",
    "remoteip=192.168.1.100",
    "enable=yes", "profile=any"
])
```

After `BLOCK_DURATION` seconds (default 60), the rule is automatically removed:
```python
subprocess.run([
    "netsh", "advfirewall", "firewall", "delete", "rule",
    "name=NETSHIELD_BLOCK_192_168_1_100"
])
```

**Verify rules in PowerShell:**
```powershell
netsh advfirewall firewall show rule name=all | findstr NETSHIELD
```

**Manually remove all NetShield rules:**
```powershell
netsh advfirewall firewall delete rule name=all | findstr NETSHIELD
```

---

## 🕵️ ICMP Smurf Detection — How It Works

A Smurf attack works like this:
```
Attacker → sends ICMP echo requests to broadcast address
           spoofing the VICTIM's IP as the source
           
All LAN hosts → reply to the VICTIM with ICMP echo replies
                (victim gets flooded by hundreds of replies)
```

NetShield detects this by counting **ICMP type 0 (echo reply)** packets
arriving at the host. When the count of replies from many sources
exceeds `SMURF_REPLY_THRESHOLD` (default 50/window), it fires a SMURF alert.

Unlike DDoS detection, the Smurf threshold is **absolute** (not adaptive),
because under normal operation a host receives very few unsolicited echo replies.

---

## ⚠️ Common Errors & Fixes (Windows-Specific)

| Error | Cause | Fix |
|---|---|---|
| `No module named 'scapy'` | Not installed | `pip install scapy` |
| `Sniffing error: No such device` | Wrong interface or Npcap not installed | Install Npcap from npcap.com |
| `OSError: [WinError 10013]` | Not running as Administrator | Re-run as Admin |
| `netsh: Access denied` | Not running as Administrator | Re-run as Admin |
| Interface shows `0.0.0.0` | Npcap sees the adapter but it has no IP | Ignore it; the correct adapter is auto-selected by matching host IP |
| ARP detection not triggering | Promiscuous mode blocked on Wi-Fi | Use a wired or Host-Only adapter in your VM |
| Dashboard not loading | Port 5000 in use | Change `DASHBOARD_PORT` in config.py |
| `colorama` not found | Not installed | `pip install colorama` (optional – script still works without it) |

---

## 🚫 Windows Limitations vs Linux

| Capability | Linux | Windows |
|---|---|---|
| Promiscuous mode (Wi-Fi) | ✅ Full support | ⚠️ Blocked by most Wi-Fi drivers – use wired/Host-Only |
| Raw socket performance | ✅ Very high | ✅ Good with Npcap |
| Firewall automation | ✅ iptables (instant, kernel-level) | ✅ netsh (user-level, ~50 ms delay) |
| IPv6 / NDP detection | ❌ Not in this version | ❌ Not in this version |
| Packet injection (attack scripts) | ✅ Full | ⚠️ Scapy can inject on Windows but requires Npcap in raw-mode |

---

*NetShield IDS/IPS Windows Edition | Cybersecurity Minor Project 2026*
