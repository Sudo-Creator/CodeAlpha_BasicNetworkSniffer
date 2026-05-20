"""
Main Network Sniffer - Entry point with CLI
"""

import argparse
import sys
from scapy.all import sniff
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
            print(f"\n{__file__} requires root/administrator privileges!")
            print("Run with: sudo python sniffer.py [options]")
            sys.exit(1)
        except Exception as e:
            print(f"\nError: {e}")
            sys.exit(1)

def get_available_interfaces():
    """Get list of available network interfaces"""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except:
        return ['eth0', 'wlan0', 'lo']

def main():
    """Parse CLI arguments and start sniffer"""
    
    interfaces = get_available_interfaces()
    default_interface = interfaces[0] if interfaces else 'eth0'
    
    parser = argparse.ArgumentParser(
        description='Network Sniffer - Capture and analyze network traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo python sniffer.py                           # Sniff all traffic on default interface
  sudo python sniffer.py -i eth0                   # Sniff on specific interface
  sudo python sniffer.py -f "tcp port 80"          # Filter HTTP traffic
  sudo python sniffer.py -f "icmp" -c 10           # Capture 10 ICMP packets
  sudo python sniffer.py -f "tcp" -v               # Verbose mode with payloads
  sudo python sniffer.py --list-interfaces         # List available interfaces
        '''
    )
    
    parser.add_argument(
        '-i', '--interface',
        default=default_interface,
        help=f'Network interface to sniff on (default: {default_interface})'
    )
    
    parser.add_argument(
        '-f', '--filter',
        default='',
        help='BPF filter string (e.g., "tcp", "udp port 53", "icmp")'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (0 = infinite)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show raw packet payloads'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    args = parser.parse_args()
    
    # Handle list-interfaces
    if args.list_interfaces:
        print("\nAvailable Network Interfaces:")
        print("-" * 40)
        for iface in interfaces:
            print(f"  • {iface}")
        print()
        return
    
    # Validate interface
    if args.interface not in interfaces:
        print(f"Error: Interface '{args.interface}' not found!")
        print(f"Available interfaces: {', '.join(interfaces)}")
        sys.exit(1)
    
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
