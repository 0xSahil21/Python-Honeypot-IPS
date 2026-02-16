import socket
import logging
import sys
import subprocess
from datetime import datetime

# --- CONFIGURATION ---
# 0.0.0.0 listens on all interfaces (Wi-Fi, Ethernet, Localhost)
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
    Checks if an IP is already blocked before adding a new rule (Idempotency).
    If not blocked, it adds an iptables DROP rule.
    """
    # 1. Safety Whitelist
    # specific IPs you NEVER want to ban (like your Gateway or Admin PC)
    whitelist = ["127.0.0.1", "localhost"] 
    
    if ip_address in whitelist:
        print(f"[*] Safety Trigger: Detected {ip_address} (Whitelisted). Not blocking.")
        return

    # 2. The Idempotency Check
    # We ask iptables: "Do you already have a DROP rule for this source IP?"
    # -C = Check. We send stdout/stderr to DEVNULL to keep the terminal clean.
    check_command = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
    
    try:
        # subprocess.call returns 0 if the command succeeds (Rule Exists)
        # It returns 1 (or other) if the command fails (Rule Does Not Exist)
        rule_exists = subprocess.call(check_command, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        
        if rule_exists == 0:
            print(f"[*] Idempotency Check: {ip_address} is already in the ban list. Skipping.")
            return # STOP HERE. Do not add a duplicate rule.
            
    except Exception as e:
        print(f"[-] Error checking iptables: {e}")

    # 3. The Block Action
    # This only runs if the check above returned 'Non-Zero' (Rule didn't exist)
    print(f"[!] AUTOMATION ENGAGED: Blocking {ip_address} in Firewall...")
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"[+] SUCCESS: {ip_address} has been neutralized.")
        logging.info(f"ACTION TAKEN - Blocked IP: {ip_address}")
    except Exception as e:
        print(f"[-] FAILED to block IP: {e}")
        print("[-] Did you run this with 'sudo'?")

def start_honeypot():
    # Create the socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow the script to restart instantly without "Address already in use" errors
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((BIND_IP, BIND_PORT))
        server_socket.listen(5)
        print(f"[*] Honey-Auditor V3 (Idempotent Defense Mode) initialized.")
        print(f"[*] Listening for 'attackers' on {BIND_IP}:{BIND_PORT}...")
    except Exception as e:
        print(f"[!] Error binding to port: {e}")
        sys.exit(1)

    while True:
        try:
            # Wait for a connection (Blocking Call)
            client_socket, client_address = server_socket.accept()
            attacker_ip = client_address[0]
            
            # Alert to Console
            print(f"\n[!] ALARM: Connection received from {attacker_ip}")
            logging.info(f"INTRUSION DETECTED - Source: {attacker_ip}")
            
            # 1. Send the Deception (Fake SSH Banner)
            fake_banner = b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\n"
            client_socket.send(fake_banner)
            client_socket.close()

# Call it TWICE to test the check
            print("--- Attempt 1 ---")
            block_ip(attacker_ip) 
            
            print("--- Attempt 2 ---")
            block_ip(attacker_ip)
            
            # 2. Active Defense (The Idempotent Blocker)
            block_ip(attacker_ip)
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down Honey-Auditor.")
            server_socket.close()
            sys.exit()

if __name__ == "__main__":
    # Root privileges are required for iptables
    start_honeypot()
