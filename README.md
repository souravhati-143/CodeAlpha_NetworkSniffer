# CodeAlpha Cybersecurity Internship Tasks

## Task 1 — Basic Network Sniffer 🔍

A Python-based network packet sniffer that captures live traffic and displays:
- Source & Destination IP addresses
- Protocol (TCP / UDP / ICMP / ARP)
- Port numbers & TCP flags
- Detected service (HTTP, SSH, DNS, etc.)
- Packet payload (hex + ASCII)
- Live statistics summary

### Requirements
```bash
pip install scapy
```
> If Scapy is not installed, the script automatically falls back to Python's built-in `socket` library (no extra install needed).

### Usage
```bash
# Basic capture (unlimited packets)
sudo python3 network_sniffer.py

# Capture 20 packets
sudo python3 network_sniffer.py --count 20

# Filter only TCP traffic
sudo python3 network_sniffer.py --filter "tcp" --count 10

# Specify a network interface
sudo python3 network_sniffer.py --iface eth0 --count 50
```

### Sample Output
```
════════════════════════════════════════════════════════════
  🔍  NETWORK SNIFFER — CodeAlpha Internship Task 1
════════════════════════════════════════════════════════════
  Interface : auto-detect
  Filter    : none (all traffic)
  Press Ctrl+C to stop and view summary
════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────
  Packet #1    [14:32:05.123]  Protocol: TCP
  Source IP      : 192.168.1.10
  Destination IP : 142.250.180.100
  TTL            : 64    Length: 60 bytes
  Source Port    : 52314
  Dest Port      : 443
  TCP Flags      : SYN
  Service Hint   : HTTPS

  📊  CAPTURE SUMMARY
════════════════════════════════════════════════════════════
  Total packets captured : 25
  Capture duration       : 12s

  Protocol Breakdown:
    TCP      ████████████████████ 18
    UDP      ████████ 6
    ICMP     █ 1
```

---

## Task 2 — Phishing Awareness Training 🎣

A professional 10-slide PowerPoint presentation covering:
- What is phishing?
- Types of phishing attacks (Email, Spear, SMS, Voice, Whaling, Clone)
- How to recognize a phishing email (with a realistic fake email mockup)
- Social engineering tactics attackers use
- Real-world phishing case studies (Google, Twitter, Uber)
- 8 best practices to protect yourself
- Interactive quiz with answers
- Key takeaways summary

**File:** `Phishing_Awareness_Training.pptx`

---

## Author
CodeAlpha Cybersecurity Intern  
Internship Program: [www.codealpha.tech](https://www.codealpha.tech)
