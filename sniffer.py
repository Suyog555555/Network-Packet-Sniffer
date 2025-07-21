# sniffer.py
from scapy.all import sniff, wrpcap
from analyzer import filter_packet
from suspicious_patterns import detect_suspicious_activity
import datetime
from scapy.all import IP, TCP

# Generate fake packet
test_packet = IP(dst="1.1.1.1")/TCP(dport=80)

# Save it
wrpcap("test_output.pcap", [test_packet])

captured_packets = []

def process_packet(packet):
    if filter_packet(packet):
        print(packet.summary())
        captured_packets.append(packet)
        detect_suspicious_activity(packet)

def start_sniffing():
    print("[*] Sniffing packets... Press Ctrl+C to stop and save .pcap")
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        save_to_pcap()


def save_to_pcap():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"captured_packets_{timestamp}.pcap"
    wrpcap(filename, captured_packets)
    print(f"\n[+] Packets saved to '{filename}'")
    print("[+] Open it in Wireshark using:\n    wireshark " + filename)

if __name__ == "__main__":
    start_sniffing()
