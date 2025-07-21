# suspicious_patterns.py

from scapy.layers.inet import TCP

ip_activity = {}

def detect_suspicious_activity(packet):
    if packet.haslayer(TCP):
        src_ip = packet[0][1].src
        dst_port = packet[TCP].dport

        if src_ip not in ip_activity:
            ip_activity[src_ip] = []

        ip_activity[src_ip].append(dst_port)

        if len(set(ip_activity[src_ip])) > 20:
            print(f"[!] Suspicious: Possible port scan from {src_ip}")
