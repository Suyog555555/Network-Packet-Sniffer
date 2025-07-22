# Network-Packet-Sniffer
# 🛡️ Network Packet Sniffer & Wireshark Analyzer

A Python-based tool that captures, filters, and analyzes network packets in real-time. It saves the captured traffic in `.pcap` format for detailed analysis using **Wireshark**.

Built as part of a Cyber Security Internship (Task 3) at **OutriX**.

---

## 🚀 Features

✅ Live packet capture using **Scapy**  
✅ Filters packets by protocol (TCP/UDP)  
✅ Detects suspicious activity (e.g., port scans)  
✅ Saves captured packets as `.pcap` files  
✅ Compatible with **Wireshark** for advanced analysis  

---

## 🧰 Tech Stack

- Python 3.x
- Scapy (packet manipulation & sniffing)
- Wireshark (for GUI-based packet analysis)

---

## 📂 Project Structure
network-packet-sniffer/
│
├── sniffer.py # Main sniffer script
├── analyzer.py # Filters packets (e.g., TCP/UDP)
├── suspicious_patterns.py # Detects patterns (e.g., port scans)
├── requirements.txt # Dependencies
├── .gitignore # Ignore cache & .pcap files
└── README.md # You're reading it

### 📥 Step 1: Clone the repository
git clone https://github.com/your-username/network-packet-sniffer.git
cd network-packet-sniffer

📦 Step 2: Install dependencies
pip install -r requirements.txt

▶️ Step 3: Run the sniffer (as root/admin)
sudo python sniffer.py    # Linux/macOS
python sniffer.py         # Windows (run as administrator)

📜 License
MIT License — free to use and modify for learning and research.

👨‍💻 Author
Suyog Talape
Cyber Security Intern @ OutriX
