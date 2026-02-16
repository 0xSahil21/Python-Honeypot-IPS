import socket
import logging
import sys
from datetime import datetime

# --- CONFIGURATION ---
# We will bind to all interfaces so you can access it from other devices in your home lab
BIND_IP = "0.0.0.0" 
# Port 2222 is often used as an alternate SSH port. It's tempting for attackers.
BIND_PORT = 2222 

# --- LOGGING SETUP ---
# This creates the "Paper Trail" for your GRC report later
logging.basicConfig(
    filename='intrusions.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def start_honeypot():
    # 1. Create the socket (The Listener)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 2. Bind the socket to the IP and Port
    try:
        server_socket.bind((BIND_IP, BIND_PORT))
        server_socket.listen(5) # Allow up to 5 pending connections
        print(f"[*] Honey-Auditor initialized.")
        print(f"[*] Listening for 'attackers' on {BIND_IP}:{BIND_PORT}...")
    except Exception as e:
        print(f"[!] Error binding to port {BIND_PORT}: {e}")
        sys.exit(1)

    # 3. The Loop (Waiting for the trap to spring)
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            
            # Alert to Console (Blue Team Awareness)
            print(f"[!] ALARM: Connection received from {client_address[0]}:{client_address[1]}")
            
            # Log to File (GRC Evidence)
            logging.info(f"INTRUSION DETECTED - Source: {client_address[0]} - Port: {client_address[1]}")
            
            # 4. Send the 'Honey' (Fake Banner)
            # This tricks nmap into thinking it found a vulnerable SSH server
            fake_banner = b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\n"
            client_socket.send(fake_banner)
            
            # Close the connection immediately
            client_socket.close()
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down Honey-Auditor.")
            server_socket.close()
            sys.exit()

if __name__ == "__main__":
    start_honeypot()
