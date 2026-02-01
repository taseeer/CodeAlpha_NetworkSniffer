from scapy.all import sniff, IP, TCP, UDP, Ether, Raw, ICMP
from datetime import datetime
import time

class NetworkSniffer:
    def __init__(self, packet_count=20):
        self.packet_count = packet_count
        self.packets_captured = 0
        self.start_time = None
        
    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            89: "OSPF"
        }
        return protocols.get(protocol_num, f"Protocol-{protocol_num}")
    
    def analyze_packet(self, packet):
        """Analyze and display packet details"""
        analysis = {}
        
        # Ethernet layer
        if packet.haslayer(Ether):
            analysis['src_mac'] = packet[Ether].src
            analysis['dst_mac'] = packet[Ether].dst
        
        # IP layer
        if packet.haslayer(IP):
            ip = packet[IP]
            analysis['src_ip'] = ip.src
            analysis['dst_ip'] = ip.dst
            analysis['ttl'] = ip.ttl
            analysis['protocol'] = self.get_protocol_name(ip.proto)
            
            # Service/port analysis
            if ip.proto == 6 and packet.haslayer(TCP):  # TCP
                tcp = packet[TCP]
                analysis['src_port'] = tcp.sport
                analysis['dst_port'] = tcp.dport
                analysis['flags'] = tcp.flags
                
                # Common ports identification
                common_ports = {
                    80: "HTTP",
                    443: "HTTPS",
                    22: "SSH",
                    25: "SMTP",
                    53: "DNS",
                    21: "FTP"
                }
                if tcp.dport in common_ports:
                    analysis['service'] = common_ports[tcp.dport]
                elif tcp.sport in common_ports:
                    analysis['service'] = common_ports[tcp.sport]
                    
            elif ip.proto == 17 and packet.haslayer(UDP):  # UDP
                udp = packet[UDP]
                analysis['src_port'] = udp.sport
                analysis['dst_port'] = udp.dport
                
            elif ip.proto == 1 and packet.haslayer(ICMP):  # ICMP
                analysis['type'] = packet[ICMP].type
                analysis['code'] = packet[ICMP].code
        
        # Packet size
        analysis['length'] = len(packet)
        
        # Timestamp
        analysis['timestamp'] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        return analysis
    
    def display_packet(self, analysis):
        """Display formatted packet information"""
        print(f"\n[{analysis['timestamp']}] Packet #{self.packets_captured}")
        print(f"   From: {analysis.get('src_ip', 'N/A')}:{analysis.get('src_port', '')}")
        print(f"   To:   {analysis.get('dst_ip', 'N/A')}:{analysis.get('dst_port', '')}")
        print(f"   Protocol: {analysis.get('protocol', 'Unknown')}")
        
        if 'service' in analysis:
            print(f"   Service: {analysis['service']}")
        
        if 'flags' in analysis:
            print(f"   TCP Flags: {analysis['flags']}")
            
        print(f"   Length: {analysis.get('length', 0)} bytes")
        print(f"   TTL: {analysis.get('ttl', 'N/A')}")
        
        if analysis.get('src_mac'):
            print(f"   MAC: {analysis['src_mac']} -> {analysis['dst_mac']}")
    
    def start_sniffing(self):
        """Start packet sniffing"""
        print("=" * 70)
        print("CodeAlpha - Advanced Network Sniffer")
        print("=" * 70)
        print(f"[!] Capturing {self.packet_count} packets")
        print("[!] Press Ctrl+C to stop\n")
        
        self.start_time = time.time()
        
        def packet_handler(packet):
            self.packets_captured += 1
            analysis = self.analyze_packet(packet)
            self.display_packet(analysis)
            
            # Show raw data for small packets (optional)
            if packet.haslayer(Raw) and len(packet[Raw]) < 100:
                try:
                    raw_data = packet[Raw].load
                    if any(32 <= byte < 127 for byte in raw_data[:50]):
                        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[:50])
                        print(f"   Data: {printable}")
                except:
                    pass
        
        try:
            # Sniff packets with filter for IP only
            sniff(filter="ip", count=self.packet_count, prn=packet_handler, store=False)
            
        except KeyboardInterrupt:
            print("\n[!] Sniffing stopped by user")
        except Exception as e:
            print(f"[✗] Error: {e}")
        finally:
            elapsed = time.time() - self.start_time
            print(f"\n[✓] Sniffing completed!")
            print(f"    Packets captured: {self.packets_captured}")
            print(f"    Time elapsed: {elapsed:.2f} seconds")
            print(f"    Average: {self.packets_captured/elapsed:.1f} packets/sec" if elapsed > 0 else "")

def main():
    # Create sniffer instance (capture 15 packets for demo)
    sniffer = NetworkSniffer(packet_count=15)
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()