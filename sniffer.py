"""
Main Network Sniffer - Entry point with CLI
"""

import argparse
import sys
import os
from scapy.all import sniff, get_if_list
from packet_handler import PacketHandler
from display import Display

class Sniffer:
    """Orchestrator class for packet sniffing"""
    
    def __init__(self, interface='eth0', filter_str='', count=0, verbose=False):
        """
        Initialize sniffer with configuration
        
        Args:
            interface: Network interface to sniff on
            filter_str: BPF filter string (e.g., "tcp port 80")
            count: Number of packets to capture (0 = infinite)
            verbose: Show raw payloads
        """
        self.interface = interface
        self.filter_str = filter_str
        self.count = count
        self.verbose = verbose
        self.display = Display(verbose=verbose)
        self.packet_handler = PacketHandler(self.display)
    
    def start(self):
        """Start packet capture"""
        try:
            self.display.print_header()
            
            print(f"Interface: {self.interface}")
            print(f"Filter: {self.filter_str if self.filter_str else 'All traffic'}")
            print(f"Count: {self.count if self.count > 0 else 'Unlimited'}")
            print(f"Verbose: {self.verbose}\n")
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_handler.process,
                filter=self.filter_str,
                count=self.count if self.count > 0 else 0,
                store=False
            )
            
        except KeyboardInterrupt:
            print("\n")
            self.display.print_footer()
        except PermissionError:
            print(f"\n❌ Permission Denied!")
            print("This program requires root/administrator privileges!")
            print("Run with: sudo python3 sniffer.py [options]")
            sys.exit(1)
        except FileNotFoundError as e:
            print(f"\n❌ Error: {e}")
            print("Make sure you have scapy installed: pip install scapy")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            sys.exit(1)

def get_available_interfaces():
    """Get list of available network interfaces"""
    try:
        interfaces = get_if_list()
        if not interfaces:
            return ['eth0', 'wlan0', 'lo']
        return interfaces
    except Exception:
        return ['eth0', 'wlan0', 'lo']

def print_welcome():
    """Print welcome banner"""
    print("""
╔════════════════════════════════════════════════════════════════╗
║          🔍 NETWORK SNIFFER - CodeAlpha Internship             ║
║     Capture, Analyze & Display Network Traffic Packets         ║
╚════════════════════════════════════════════════════════════════╝
""")

def main():
    """Parse CLI arguments and start sniffer"""
    
    interfaces = get_available_interfaces()
    default_interface = interfaces[0] if interfaces else 'eth0'
    
    parser = argparse.ArgumentParser(
        prog='Network Sniffer',
        description='🔍 Capture and analyze network traffic packets in real-time',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
╔══════════════════════════════════════════════════════════════════╗
║                         USAGE EXAMPLES                          ║
╚══════════════════════════════════════════════════════════════════╝

BASIC USAGE:
  sudo python3 sniffer.py                    # Sniff all traffic
  sudo python3 sniffer.py --help             # Show this help menu
  sudo python3 sniffer.py --list-interfaces  # List available interfaces

INTERFACE SELECTION:
  sudo python3 sniffer.py -i eth0            # Sniff on eth0
  sudo python3 sniffer.py -i wlan0           # Sniff on wlan0
  sudo python3 sniffer.py -i lo              # Sniff on loopback

PROTOCOL FILTERING:
  sudo python3 sniffer.py -f "tcp"           # Capture TCP only
  sudo python3 sniffer.py -f "udp"           # Capture UDP only
  sudo python3 sniffer.py -f "icmp"          # Capture ICMP (ping)
  sudo python3 sniffer.py -f "arp"           # Capture ARP packets

PORT-SPECIFIC FILTERING:
  sudo python3 sniffer.py -f "tcp port 80"   # HTTP traffic
  sudo python3 sniffer.py -f "tcp port 443"  # HTTPS traffic
  sudo python3 sniffer.py -f "udp port 53"   # DNS traffic
  sudo python3 sniffer.py -f "port 22"       # SSH traffic

PACKET LIMITING:
  sudo python3 sniffer.py -c 10              # Capture 10 packets
  sudo python3 sniffer.py -c 100 -f "tcp"    # Capture 100 TCP packets
  sudo python3 sniffer.py -c 50 -v           # Capture 50 with payloads

VERBOSE MODE (Show Payloads):
  sudo python3 sniffer.py -v                 # Show raw data
  sudo python3 sniffer.py -f "tcp" -v -c 20  # TCP with payloads

COMPLEX FILTERS:
  sudo python3 sniffer.py -f "tcp and port 80"
  sudo python3 sniffer.py -f "not arp"
  sudo python3 sniffer.py -f "src 192.168.1.1"
  sudo python3 sniffer.py -f "dst 8.8.8.8"

FULL EXAMPLES:
  sudo python3 sniffer.py -i eth0 -f "tcp port 443" -c 50 -v
  sudo python3 sniffer.py -i wlan0 -f "icmp" -c 10
  sudo python3 sniffer.py -f "udp port 53" -v

╔══════════════════════════════════════════════════════════════════╗
║                      REQUIREMENTS                               ║
╚══════════════════════════════════════════════════════════════════╝
  • Root/Administrator privileges (run with sudo)
  • Python 3.7+
  • Scapy library: pip install -r requirements.txt
  • Colorama library (included in requirements.txt)

╔══════════════════════════════════════════════════════════════════╗
║                    PROTOCOL SUPPORT                             ║
╚══════════════════════════════════════════════════════════════════╝
  ✓ TCP  - Ports, flags (SYN, ACK, FIN, RST, PSH, URG)
  ✓ UDP  - Ports, length
  ✓ ICMP - Type, code (ping requests/replies)
  ✓ ARP  - Address resolution protocol
  ✓ IPv4 - Source/destination IPs, TTL

Press Ctrl+C to stop capturing packets.
        '''
    )
    
    parser.add_argument(
        '-i', '--interface',
        default=default_interface,
        metavar='IFACE',
        help=f'Network interface to sniff on (default: {default_interface})'
    )
    
    parser.add_argument(
        '-f', '--filter',
        default='',
        metavar='FILTER',
        help='BPF filter string (e.g., "tcp", "udp port 53", "icmp", "not arp")'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        metavar='NUM',
        help='Number of packets to capture (0 = infinite, default: 0)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show raw packet payloads (verbose output)'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Network Sniffer v1.0 (CodeAlpha Internship)'
    )
    
    args = parser.parse_args()
    
    # Handle list-interfaces
    if args.list_interfaces:
        print_welcome()
        print("📋 Available Network Interfaces:\n")
        for idx, iface in enumerate(interfaces, 1):
            print(f"  {idx}. {iface}")
        print()
        print("Usage: sudo python3 sniffer.py -i <interface_name>\n")
        return
    
    # Validate interface
    if args.interface not in interfaces:
        print(f"\n❌ Error: Interface '{args.interface}' not found!")
        print(f"\n📋 Available interfaces: {', '.join(interfaces)}")
        print(f"\nUse: sudo python3 sniffer.py --list-interfaces")
        print(f"Or:  sudo python3 sniffer.py -i <interface_name>\n")
        sys.exit(1)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("\n⚠️  Warning: This program should be run with root privileges!")
        print("Run with: sudo python3 sniffer.py [options]\n")
    
    print_welcome()
    
    # Create and start sniffer
    sniffer = Sniffer(
        interface=args.interface,
        filter_str=args.filter,
        count=args.count,
        verbose=args.verbose
    )
    
    sniffer.start()

if __name__ == '__main__':
    main()
