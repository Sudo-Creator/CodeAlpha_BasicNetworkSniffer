# Network Sniffer - CodeAlpha Internship Task 1

A Python-based network packet sniffer that captures, analyzes, and displays network traffic with detailed protocol information.

## 📋 Features

- **Real-time Packet Capture**: Sniff network packets using Scapy
- **Protocol Analysis**: Parse TCP, UDP, ICMP, and Ethernet layers
- **Colored Output**: Color-coded protocol identification for easy reading
- **Flexible Filtering**: BPF filter support (tcp, udp, icmp, port-specific, etc.)
- **Packet Count Control**: Capture unlimited packets or specify a limit
- **Verbose Mode**: Display raw packet payloads
- **MAC Address Tracking**: Shows source and destination MAC addresses
- **Port Information**: Displays source and destination ports for TCP/UDP
- **TCP Flags**: Shows TCP control flags (SYN, ACK, FIN, etc.)

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- Linux/macOS (root access required) or Windows (Administrator)

### Setup

```bash
# Clone the repository
git clone https://github.com/Sudo-Creator/CodeAlpha_BasicNetworkSniffer
cd CodeAlpha_BasicNetworkSniffer

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Usage
```bash
# Sniff all traffic on default interface
sudo python sniffer.py

# Sniff on specific interface
sudo python sniffer.py -i eth0

# List available interfaces
sudo python sniffer.py --list-interfaces
```

### Advanced Filtering
```bash
# Capture TCP traffic only
sudo python sniffer.py -f "tcp"

# Capture UDP traffic only
sudo python sniffer.py -f "udp"

# Capture ICMP (ping) traffic
sudo python sniffer.py -f "icmp"

# Capture HTTP traffic on port 80
sudo python sniffer.py -f "tcp port 80"

# Capture HTTPS traffic on port 443
sudo python sniffer.py -f "tcp port 443"

# Capture DNS traffic on port 53
sudo python sniffer.py -f "udp port 53"
```

### Packet Limiting
```bash
# Capture only 10 packets
sudo python sniffer.py -c 10

# Capture 100 TCP packets
sudo python sniffer.py -f "tcp" -c 100

# Capture 50 packets with verbose output
sudo python sniffer.py -c 50 -v
```

### Verbose Mode
```bash
# Show packet payloads
sudo python sniffer.py -v

# Combine all options
sudo python sniffer.py -i eth0 -f "tcp port 80" -c 20 -v
```

## 📊 Output Example

```
[Packet #1] 2024-01-15 14:23:45.123 | TCP
  MAC: 08:00:27:BD:86:A4 → 52:54:00:12:35:02
  IP: 192.168.1.100:54321 → 8.8.8.8:443
  Flags: SYN

[Packet #2] 2024-01-15 14:23:45.145 | TCP
  MAC: 52:54:00:12:35:02 → 08:00:27:BD:86:A4
  IP: 8.8.8.8:443 → 192.168.1.100:54321
  Flags: SYN,ACK

[Packet #3] 2024-01-15 14:23:45.156 | UDP
  MAC: 08:00:27:BD:86:A4 → 08:08:08:08:08:08
  IP: 192.168.1.100:53012 → 8.8.8.8:53
```

## 📁 Project Structure

```
CodeAlpha_BasicNetworkSniffer/
├── sniffer.py          # Entry point + CLI argument parsing
├── packet_handler.py   # Core packet parsing logic
├── display.py          # Output formatting with colors
├── utils.py            # Helper functions (timestamps, protocol maps)
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## 🔍 Classes & Methods

### `Sniffer` (sniffer.py)
- `__init__(interface, filter_str, count, verbose)` - Initialize sniffer
- `start()` - Begin packet capture

### `PacketHandler` (packet_handler.py)
- `process(packet)` - Main callback for each captured packet
- `parse_ethernet(packet, info)` - Extract MAC addresses
- `parse_ip(packet, info)` - Extract IP layer info
- `parse_tcp(packet, info)` - Extract TCP layer info
- `parse_udp(packet, info)` - Extract UDP layer info
- `parse_icmp(packet, info)` - Extract ICMP layer info
- `parse_payload(packet, info)` - Extract raw payload

### `Display` (display.py)
- `print_header()` - Print startup banner
- `print_packet(info_dict)` - Format and display packet info
- `print_footer()` - Print exit summary

## 🔐 Protocol Support

| Protocol | Supported | Details |
|----------|-----------|----------|
| TCP | ✅ | Ports, flags (SYN, ACK, FIN, RST, PSH, URG) |
| UDP | ✅ | Ports, length |
| ICMP | ✅ | Type, code (ping requests/replies) |
| Ethernet | ✅ | MAC addresses |
| IPv4 | ✅ | Source/destination IPs, TTL |
| Raw Payload | ✅ | UTF-8 or hex representation |

## ⚠️ Requirements

- **Root/Administrator Privileges**: Raw socket access requires elevated permissions
- **Linux/macOS Recommended**: Best compatibility on Unix-like systems
- **Windows**: Requires running as Administrator

## 🧪 Testing Locally

### Test on Loopback Interface
```bash
# Terminal 1: Start sniffer on loopback
sudo python sniffer.py -i lo -f "tcp port 8000" -v

# Terminal 2: Make a request
curl http://localhost:8000
```

### Test with Ping
```bash
# Terminal 1: Capture ICMP
sudo python sniffer.py -f "icmp"

# Terminal 2: Send ping
ping 8.8.8.8
```

### Test with DNS
```bash
# Terminal 1: Capture DNS
sudo python sniffer.py -f "udp port 53"

# Terminal 2: Resolve domain
nslookup google.com
```

## 📝 Scapy Reference

### Checking for Layers
```python
packet.haslayer(IP)       # Check for IP layer
packet.haslayer(TCP)      # Check for TCP layer
packet.haslayer(UDP)      # Check for UDP layer
packet.haslayer(ICMP)     # Check for ICMP layer
packet.haslayer(Raw)      # Check for raw payload
```

### Accessing Fields
```python
packet[IP].src            # Source IP
packet[IP].dst            # Destination IP
packet[TCP].sport         # TCP source port
packet[TCP].dport         # TCP destination port
packet[TCP].flags         # TCP flags
packet[UDP].sport         # UDP source port
packet[UDP].dport         # UDP destination port
packet[ICMP].type         # ICMP type
packet[Raw].load          # Raw payload bytes
```

## 🐛 Troubleshooting

### Permission Denied
```
Error: sniffer.py requires root/administrator privileges!
```
**Solution**: Run with `sudo`
```bash
sudo python sniffer.py
```

### Interface Not Found
```
Error: Interface 'eth0' not found!
Available interfaces: lo, wlan0
```
**Solution**: Use `--list-interfaces` to see available options
```bash
sudo python sniffer.py --list-interfaces
```

### No Packets Captured
- Check your filter syntax (e.g., `"tcp port 80"`)
- Ensure the interface is active and has traffic
- Try without filters: `sudo python sniffer.py`

## 📚 Learning Outcomes

After completing this project, you'll understand:
- How network packets are structured
- The OSI model and packet layers
- TCP/IP protocol fundamentals
- How to capture and analyze live network traffic
- BPF (Berkeley Packet Filter) syntax
- Python networking libraries

## 📄 License

Educational project for CodeAlpha Internship

## 👨‍💻 Author

**Sudo-Creator**  
GitHub: [@Sudo-Creator](https://github.com/Sudo-Creator)

---

**Project Status**: ✅ Complete  
**Last Updated**: 2026-05-20
