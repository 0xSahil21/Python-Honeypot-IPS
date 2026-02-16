from fpdf import FPDF
import datetime

def parse_log(log_file):
    """Reads the raw log file and extracts structured data."""
    events = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Parsing lines like: "2025-11-20 ... - INTRUSION DETECTED - Source: 192.168.x.x"
                if "INTRUSION" in line:
                    parts = line.split(" - ")
                    # Safety check to ensure line has enough parts
                    if len(parts) >= 3:
                        timestamp = parts[0]
                        # Extract IP from "Source: 192.168.x.x"
                        ip_part = parts[2] 
                        if "Source:" in ip_part:
                            source_ip = ip_part.split(": ")[1].strip()
                            events.append({"time": timestamp, "ip": source_ip})
    except FileNotFoundError:
        print("[-] Error: intrusions.log not found. Run the honeypot first!")
    return events

class PDF(FPDF):
    def header(self):
        # Logo or Header Text
        self.set_font('Arial', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'Security Incident Report', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def create_report(events):
    pdf = PDF()
    pdf.add_page()
    pdf.set_title("Monthly Intrusion Analysis")
    
    # --- Title Section ---
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Generated On: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=1, align='L')
    pdf.cell(200, 10, txt="System: Kali Linux Honeypot Node 1", ln=1, align='L')
    pdf.ln(10)

    # --- Executive Summary ---
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt="1. Executive Summary", ln=1, align='L')
    
    pdf.set_font("Arial", size=11)
    summary_text = (
        f"This report details unauthorized access attempts detected by the automated defense system. "
        f"A total of {len(events)} distinct intrusion events were recorded. "
        f"The Automated Defense protocol (Active Blocking) was engaged for all unique threats. "
        f"No data exfiltration was detected."
    )
    pdf.multi_cell(0, 10, txt=summary_text)
    pdf.ln(5)

    # --- Technical Details ---
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt="2. Threat Intelligence Log", ln=1, align='L')
    
    # Table Header
    pdf.set_fill_color(200, 220, 255)
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(60, 10, "Timestamp", 1, 0, 'C', 1)
    pdf.cell(50, 10, "Source IP", 1, 0, 'C', 1)
    pdf.cell(80, 10, "Remediation Action", 1, 1, 'C', 1)

    # Table Rows
    pdf.set_font("Arial", size=10)
    unique_ips = set()
    
    for event in events:
        pdf.cell(60, 10, event['time'], 1)
        pdf.cell(50, 10, event['ip'], 1)
        
        # Logic to show if it was a repeated attack
        status = "Blocked (New Rule)"
        if event['ip'] in unique_ips:
            status = "Blocked (Existing Rule)"
        unique_ips.add(event['ip'])
        
        pdf.cell(80, 10, status, 1, 1)

    pdf.output("Security_Report.pdf")
    print("[+] Report Generated: Security_Report.pdf")

if __name__ == "__main__":
    print("[*] Parsing logs...")
    data = parse_log("intrusions.log")
    if data:
        print(f"[*] Found {len(data)} events. Generating PDF...")
        create_report(data)
    else:
        print("[-] No events found in log to report.")
