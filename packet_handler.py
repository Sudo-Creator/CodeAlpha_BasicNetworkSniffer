"""
Core packet parsing and handling logic
"""
from scapy.all import IP, IPv6, ICMP, TCP, UDP, Raw, Ether
from utils import get_protocol_name, get_timestamp, format_bytes

class PacketHandler:
    """Core class for processing and parsing captured packets"""
    
    def __init__(self, display):
        self.display = display
    
    def process(self, packet):
        """Main callback - receives each captured packet from Scapy"""
        info = {
            'timestamp': get_timestamp(),
            'protocol': 'Unknown',
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_port': None,
            'dst_port': None,
            'flags': '',
            'payload': '',
            'src_mac': 'N/A',
            'dst_mac': 'N/A',
        }
        
        # Parse Ethernet layer (MAC addresses)
        if packet.haslayer(Ether):
            info = self.parse_ethernet(packet, info)
        
        # Parse IP layer (IPv4)
        if packet.haslayer(IP):
            info = self.parse_ip(packet, info)
            
            # Parse TCP layer
            if packet.haslayer(TCP):
                info = self.parse_tcp(packet, info)
            
            # Parse UDP layer
            elif packet.haslayer(UDP):
                info = self.parse_udp(packet, info)
            
            # Parse ICMP layer
            elif packet.haslayer(ICMP):
                info = self.parse_icmp(packet, info)
        
        # Parse IPv6 layer
        elif packet.haslayer(IPv6):
            info = self.parse_ipv6(packet, info)
            
            # Parse TCP layer
            if packet.haslayer(TCP):
                info = self.parse_tcp(packet, info)
            
            # Parse UDP layer
            elif packet.haslayer(UDP):
                info = self.parse_udp(packet, info)
        
        # Parse payload
        if packet.haslayer(Raw):
            info = self.parse_payload(packet, info)
        
        # Display the packet
        self.display.print_packet(info)
    
    def parse_ethernet(self, packet, info):
        """Extract MAC addresses from Ethernet layer"""
        try:
            eth = packet[Ether]
            info['src_mac'] = eth.src
            info['dst_mac'] = eth.dst
        except Exception:
            pass
        
        return info
    
    def parse_ip(self, packet, info):
        """Extract source IP, destination IP, TTL, and protocol number"""
        try:
            ip_layer = packet[IP]
            info['src_ip'] = ip_layer.src
            info['dst_ip'] = ip_layer.dst
            info['ttl'] = ip_layer.ttl
            info['protocol'] = get_protocol_name(ip_layer.proto)
        except Exception:
            pass
        
        return info
    
    def parse_ipv6(self, packet, info):
        """Extract source IP, destination IP from IPv6 layer"""
        try:
            ipv6_layer = packet[IPv6]
            info['src_ip'] = ipv6_layer.src
            info['dst_ip'] = ipv6_layer.dst
            info['protocol'] = 'IPv6'
        except Exception:
            pass
        
        return info
    
    def parse_tcp(self, packet, info):
        """Extract TCP source/destination ports and flags"""
        try:
            tcp_layer = packet[TCP]
            info['src_port'] = tcp_layer.sport
            info['dst_port'] = tcp_layer.dport
            info['flags'] = str(tcp_layer.flags)
            info['protocol'] = 'TCP'
        except Exception:
            pass
        
        return info
    
    def parse_udp(self, packet, info):
        """Extract UDP source/destination ports and length"""
        try:
            udp_layer = packet[UDP]
            info['src_port'] = udp_layer.sport
            info['dst_port'] = udp_layer.dport
            info['udp_len'] = udp_layer.len
            info['protocol'] = 'UDP'
        except Exception:
            pass
        
        return info
    
    def parse_icmp(self, packet, info):
        """Extract ICMP type and code"""
        try:
            icmp_layer = packet[ICMP]
            info['icmp_type'] = icmp_layer.type
            info['icmp_code'] = icmp_layer.code
            info['protocol'] = 'ICMP'
        except Exception:
            pass
        
        return info
    
    def parse_payload(self, packet, info):
        """Extract and format raw payload bytes"""
        try:
            if packet.haslayer(Raw):
                raw_load = packet[Raw].load
                info['payload'] = format_bytes(raw_load, max_length=50)
        except Exception:
            pass
        
        return info
