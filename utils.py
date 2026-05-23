"""
Utility functions for the network sniffer
"""
import socket
from datetime import datetime

# Protocol number to name mapping
PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6",
    50: "ESP",
    51: "AH",
}

def get_protocol_name(proto_num):
    """Convert protocol number to name"""
    return PROTOCOL_MAP.get(proto_num, f"Other ({proto_num})")

def get_timestamp():
    """Get current timestamp in readable format"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def format_bytes(data, max_length=50):
    """Format bytes for display, try UTF-8 decode first"""
    try:
        decoded = data.decode('utf-8', errors='ignore')
        # Replace unprintable characters
        decoded = ''.join(c if c.isprintable() else '.' for c in decoded)
        if len(decoded) > max_length:
            return decoded[:max_length] + "..."
        return decoded
    except Exception:
        # Fall back to hex representation
        hex_str = data.hex()
        if len(hex_str) > max_length:
            return hex_str[:max_length] + "..."
        return hex_str

def format_flags(flags_str):
    """Convert TCP flags string to readable format"""
    if not flags_str:
        return ""

    flag_map = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }

    flags = [flag_map.get(f, f) for f in flags_str]
    return ','.join(flags)

def resolve_hostname(ip):
    """Resolve an IP address to a hostname via reverse DNS lookup.
    Returns the hostname string, or None if resolution fails."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        # Only return if it's actually different from the IP itself
        if hostname and hostname != ip:
            return hostname
        return None
    except Exception:
        return None
