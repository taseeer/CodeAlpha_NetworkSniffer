from scapy.all import sniff, IP, TCP, UDP, Ether, Raw
import sys

def packet_callback(packet):
    # Display basic packet info
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"\n[+] Packet Captured:")
        print(f"   Source IP: {ip_src}")
        print(f"   Destination IP: {ip_dst}")
        
        if protocol == 6 and packet.haslayer(TCP):
            print(f"   Protocol: TCP")
            if packet[TCP].dport:
                print(f"   Destination Port: {packet[TCP].dport}")
        elif protocol == 17 and packet.haslayer(UDP):
            print(f"   Protocol: UDP")
            if packet[UDP].dport:
                print(f"   Destination Port: {packet[UDP].dport}")
        else:
            print(f"   Protocol: {protocol}")
        
        # Show packet summary (safe view)
        print(f"   Summary: {packet.summary()}")
        
        # Only show first 100 bytes of raw data if exists
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            print(f"   Data (first 100 chars): {raw_data[:100]}")
    
    return len(packet)

def main():
    print("=" * 60)
    print("CodeAlpha - Basic Network Sniffer (Safe Mode)")
    print("=" * 60)
    print("[!] This sniffer will capture only 10 packets")
    print("[!] Press Ctrl+C to stop earlier")
    print("[!] Starting capture...\n")
    
    try:
        # Capture ONLY 10 packets - safe limit
        packets = sniff(count=10, prn=packet_callback, store=False)
        print(f"\n[✓] Captured {len(packets)} packets safely")
        
    except PermissionError:
        print("[✗] Error: Need administrator privileges to sniff")
        print("[!] Run as administrator if you want full packet capture")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[✗] Error: {e}")

if __name__ == "__main__":
    main()