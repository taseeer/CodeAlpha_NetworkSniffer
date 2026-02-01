# CodeAlpha - Basic Network Sniffer

## Project Overview
This is a Python-based network packet sniffer developed for CodeAlpha Cybersecurity Internship Task 1. The tool captures and analyzes network traffic to understand packet structure, protocols, and data flow.

## Features
- Captures IP packets from network interfaces
- Analyzes TCP, UDP, and ICMP protocols
- Displays source/destination IPs and ports
- Shows packet size, TTL, and timestamps
- Identifies common services (HTTP, HTTPS, DNS, etc.)
- Safe operation with packet count limits

## Requirements
- Python 3.6+
- Scapy 2.7.0

## Installation
```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
Usage
# Basic sniffer (10 packets)
python basic_sniffer.py

# Advanced sniffer (15 packets with detailed analysis)
python advanced_sniffer.py

# Run as Administrator for best results on Windows
Output Example
[14:30:25.123] Packet #1
   From: 192.168.1.100:54321
   To:   8.8.8.8:53
   Protocol: UDP
   Service: DNS
   Length: 78 bytes
   TTL: 64
   Safety Features
Limited packet capture (prevents infinite sniffing)

No packet modification or injection

Focus on analysis only

Works within virtual environment

Learning Outcomes
Understanding network packet structure

Analyzing different protocol layers

Identifying network services by port numbers

Safe packet capture techniques
## Testing
Run the test script to verify installation:
```bash
python test_sniffer.py
Project Structure
CodeAlpha_BasicNetworkSniffer/
├── basic_sniffer.py     # Basic packet sniffer (10 packets)
├── advanced_sniffer.py  # Enhanced analyzer with detailed output
├── test_sniffer.py      # Dependency verification script
├── requirements.txt     # Required Python packages
├── README.md           # Project documentation
└── screenshots/        # Output screenshots (optional)
Sample Output
The sniffer captures packets showing:

Source and destination IP addresses

Protocol types (TCP/UDP/ICMP)

Port numbers and service identification

Packet sizes and TTL values

MAC addresses for local network analysis

TCP flags for connection analysis

Educational Value
This project demonstrates:

Network packet capture fundamentals

Protocol analysis techniques

Safe ethical hacking practices

Python networking programming

Real-world cybersecurity monitoring

Compliance
This tool is for educational purposes only. Use only on networks you own or have permission to monitor.


Author
[Taseer Ullah] - CodeAlpha Cybersecurity Intern