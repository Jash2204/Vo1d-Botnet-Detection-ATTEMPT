import pyshark
import scapy.all as scapy
import socket
import time
import json

# Define known Vo1d botnet indicators
VO1D_C2_DOMAINS = ["ssl8rrs2.com", "unknownproxy.xyz"]
VO1D_C2_IPS = ["3.146.93.253", "185.234.217.6"]
SUSPICIOUS_PORTS = [55503, 55600]
DNS_ENTROPY_THRESHOLD = 3.5  # Adjusted threshold for detecting DGA domains

# Function to calculate entropy for detecting DGA domains
def calculate_entropy(domain):
    from collections import Counter
    import math
   
    count = Counter(domain)
    length = len(domain)
    return -sum((freq / length) * math.log2(freq / length) for freq in count.values())

# Function to check if a domain is suspicious
def is_suspicious_domain(domain):
    if domain in VO1D_C2_DOMAINS:
        return True, "Matches known Vo1d C2 domain"
    if calculate_entropy(domain) > DNS_ENTROPY_THRESHOLD:
        return True, "High entropy, possible DGA domain"
    return False, ""

# Function to process DNS packets
def process_dns(packet):
    if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
        domain = packet.dns.qry_name
        is_suspicious, reason = is_suspicious_domain(domain)
        if is_suspicious:
            print(f"[ALERT] Suspicious DNS Query: {domain} - {reason}")

# Function to process network packets
def process_packet(packet):
    try:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
           
            # Detect C2 communication
            if dst_ip in VO1D_C2_IPS:
                print(f"[ALERT] Connection to Vo1d C2 IP: {dst_ip}")
               
            # Detect unusual port usage
            if hasattr(packet, 'tcp') and int(packet.tcp.dstport) in SUSPICIOUS_PORTS:
                print(f"[ALERT] Connection to unusual port {packet.tcp.dstport} by {src_ip}")
   
        # Process DNS queries separately
        process_dns(packet)
   
    except Exception as e:
        print(f"[ERROR] Packet processing error: {e}")

# Function to start monitoring network traffic
def start_monitor(interface):
    print(f"[*] Starting network capture on {interface}...")
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously(packet_count=0):
        process_packet(packet)

if __name__ == "__main__":
    network_interface = "eth0"  # Change this to match the actual interface (e.g., wlan0 for WiFi)
    start_monitor(network_interface)