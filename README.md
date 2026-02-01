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