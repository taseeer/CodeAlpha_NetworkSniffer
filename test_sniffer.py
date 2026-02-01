#!/usr/bin/env python3
"""
Test script for CodeAlpha Network Sniffer
This script verifies that all dependencies are installed correctly.
"""

import sys
import subprocess

def check_package(package_name):
    """Check if a Python package is installed."""
    try:
        __import__(package_name)
        print(f"[✓] {package_name} is installed")
        return True
    except ImportError:
        print(f"[✗] {package_name} is NOT installed")
        return False

def main():
    print("CodeAlpha Network Sniffer - Dependency Check")
    print("=" * 50)
    
    # Check Python version
    print(f"Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Check required packages
    required = ["scapy"]
    all_installed = True
    
    for package in required:
        if not check_package(package):
            all_installed = False
    
    if all_installed:
        print("\n[✓] All dependencies are installed correctly!")
        print("You can run:")
        print("  python sniffer.py        (Basic version)")
        print("  python advanced_sniffer.py (Enhanced version)")
    else:
        print("\n[!] Some dependencies are missing.")
        print("Install them using: pip install -r requirements.txt")

if __name__ == "__main__":
    main()