"""
Display formatting for network sniffer output
"""
from colorama import Fore, Style, init
from utils import format_flags

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class Display:
    """Handles all output formatting and display"""
    
    PROTOCOL_COLORS = {
        "TCP":   Fore.GREEN,
        "UDP":   Fore.YELLOW,
        "ICMP":  Fore.CYAN,
        "ARP":   Fore.RED,
        "IPv6":  Fore.MAGENTA,
        "Other": Fore.WHITE,
    }
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.packet_count = 0
    
    def print_header(self):
        """Print sniffer banner on startup"""
        print(f"\n{Fore.BLUE}{'='*80}")
        print(f"{Fore.BLUE}🔍 NETWORK SNIFFER - Packet Capture & Analysis")
        print(f"{Fore.BLUE}{'='*80}")
        print(f"{Fore.CYAN}Starting packet capture... Press Ctrl+C to stop")
        print(f"{Fore.BLUE}{'-'*80}{Style.RESET_ALL}\n")
    
    def print_packet(self, info_dict):
        """Print formatted summary per packet"""
        self.packet_count += 1
        
        timestamp = info_dict.get('timestamp', '')
        protocol  = info_dict.get('protocol', 'Unknown')
        src_ip    = info_dict.get('src_ip', 'N/A')
        dst_ip    = info_dict.get('dst_ip', 'N/A')
        src_port  = info_dict.get('src_port', '')
        dst_port  = info_dict.get('dst_port', '')
        flags     = info_dict.get('flags', '')
        payload   = info_dict.get('payload', '')
        src_mac   = info_dict.get('src_mac', 'N/A')
        dst_mac   = info_dict.get('dst_mac', 'N/A')
        arp_op    = info_dict.get('arp_op', '')
        
        color = self.PROTOCOL_COLORS.get(protocol, Fore.WHITE)
        
        # Print packet number and basic info
        print(f"{Fore.WHITE}[Packet #{self.packet_count}] {timestamp} | {color}{protocol}{Style.RESET_ALL}")
        
        # Print MAC addresses
        print(f"  {Fore.LIGHTBLACK_EX}MAC: {src_mac} → {dst_mac}{Style.RESET_ALL}")
        
        # Print IP addresses and ports
        if src_port and dst_port:
            print(f"  {Fore.LIGHTBLUE_EX}IP: {src_ip}:{src_port} → {dst_ip}:{dst_port}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.LIGHTBLUE_EX}IP: {src_ip} → {dst_ip}{Style.RESET_ALL}")
        
        # Print ARP operation if present
        if arp_op:
            print(f"  {Fore.RED}Operation: {arp_op}{Style.RESET_ALL}")
        
        # Print TCP flags if present
        if flags:
            formatted_flags = format_flags(flags)
            print(f"  {Fore.LIGHTYELLOW_EX}Flags: {formatted_flags}{Style.RESET_ALL}")
        
        # Print payload if verbose mode is enabled
        if self.verbose and payload:
            print(f"  {Fore.LIGHTGREEN_EX}Payload: {payload}{Style.RESET_ALL}")
        
        print()  # Blank line for readability
    
    def print_footer(self):
        """Print summary on exit"""
        print(f"\n{Fore.BLUE}{'='*80}")
        print(f"{Fore.CYAN}Capture Complete: {self.packet_count} packets captured")
        print(f"{Fore.BLUE}{'='*80}{Style.RESET_ALL}\n")
