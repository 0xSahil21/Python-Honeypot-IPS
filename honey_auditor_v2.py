import socket
import logging
import sys
import subprocess # NEW: Allows us to run shell commands
from datetime import datetime

# --- CONFIGURATION ---
BIND_IP = "0.0.0.0" 
BIND_PORT = 2222 

# --- LOGGING SETUP ---
logging.basicConfig(
    filename='intrusions.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def block_ip(ip_address):
    """
    Executes an iptables command to drop traffic from the specific IP.
    """
    # --- GRC/SAFETY CHECK ---
    # In a real environment, you MUST have a whitelist.
    # You never want to accidentally auto-ban your own admin server or Gateway.
    whitelist = ["127.0.0.1", "localhost"] 
    
    if ip_address in whitelist:
        print(f"[*] Safety Trigger: Detected {ip_address} (Whitelisted). Not blocking.")
        return

    print(f"[!] AUTOMATION ENGAGED: Blocking {ip_address} in Firewall...")
    
    # The Command: sudo iptables -A INPUT -s <IP> -j DROP
    # -A INPUT : Append to the Input Chain (Incoming traffic)
    # -s <IP>  : The Source IP to look for
    # -j DROP  : The Action (Jump to Drop) - silently discard the packet
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"[+] SUCCESS: {ip_address} has been neutralized.")
        logging.info(f"ACTION TAKEN - Blocked IP: {ip_address}")
    except Exception as e:
        print(f"[-] FAILED to block IP: {e}")
        print("[-] Did you run this with 'sudo'?")

def start_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows restarting script instantly
    
    try:
        server_socket.bind((BIND_IP, BIND_PORT))
        server_socket.listen(5)
        print(f"[*] Honey-Auditor (Active Defense Mode) initialized.")
        print(f"[*] Listening on {BIND_IP}:{BIND_PORT}...")
    except Exception as e:
        print(f"[!] Error binding to port: {e}")
        sys.exit(1)

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            attacker_ip = client_address[0]
            
            print(f"\n[!] ALARM: Connection received from {attacker_ip}")
            logging.info(f"INTRUSION DETECTED - Source: {attacker_ip}")
            
            # 1. Send the Deception
            fake_banner = b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\n"
            client_socket.send(fake_banner)
            client_socket.close()
            
            # 2. Active Defense (The Blue Team Response)
            block_ip(attacker_ip)
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            server_socket.close()
            sys.exit()

if __name__ == "__main__":
    start_honeypot()
