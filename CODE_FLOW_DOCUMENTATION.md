# ARP Cache Poisoning & Man-in-the-Middle Attack - Code Flow Documentation

## Overview
This project implements an ARP cache poisoning attack combined with HTTP packet injection to perform a Man-in-the-Middle (MITM) attack. The attack allows an attacker to intercept and modify HTTP traffic between a victim and the network gateway.

## Project Structure

### Files Overview
- **`arp_mitm_attack.py`** - Main attack script (ARP poisoning + HTTP injection)
- **`http_injection_mitmproxy.py`** - Alternative HTTP injection using mitmproxy
- **`arp_restore.py`** - ARP table restoration utility
- **`raw/mac_address_discovery.py`** - MAC address discovery utility
- **`config.py`** - Centralized configuration for all tools
- **`arp_defense_monitor.py`** - Defense monitoring system
- **`secure_arp_client.py`** - Secure ARP client with validation
- **`network_hardening_tools.py`** - Network-level protection measures
- **`network_device_scanner.py`** - Comprehensive network device discovery

## Configuration System

### Centralized Configuration (`config.py`)
The project uses a centralized configuration system that manages:

- **Network Settings**: Interface, IP ranges, timeouts
- **Attack Parameters**: Target IPs, MAC addresses, injection payloads
- **Defense Settings**: Alert thresholds, monitoring intervals
- **Security Options**: Safety checks, legal warnings, cleanup settings

#### Configuration Classes:
- `NetworkConfig` - Network interface and connectivity settings
- `AttackConfig` - Attack target configuration and payloads
- `DefenseConfig` - Defense system parameters
- `ScannerConfig` - Network discovery settings
- `SecurityConfig` - Safety and legal compliance settings

#### User Configuration:
```bash
# Copy template and customize
cp user_config_template.py user_config.py
# Edit your network-specific values
nano user_config.py
```

## Detailed Code Flow Analysis

### 1. Main Attack Script (`arp_mitm_attack.py`)

#### Configuration Import
```python
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig

# Use configuration values
victim_ip = AttackConfig.VICTIM_IP
gateway_ip = AttackConfig.GATEWAY_IP
interface = NetworkConfig.INTERFACE
```

#### Network Configuration
The script imports all network parameters from the centralized config:
- Victim IP and MAC address
- Gateway IP and MAC address 
- Network interface
- Injection payloads

#### Attack Phases

##### Phase 1: System Preparation
1. **IP Forwarding Enable** (`enable_ip_forwarding()`)
   - Enables packet forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
   - Allows attacker machine to forward packets between victim and gateway

##### Phase 2: ARP Cache Poisoning
2. **ARP Poisoning Function** (`poison()`)
   ```python
   def poison(victim_ip, victim_mac, spoof_ip):
       pkt = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
       sendp(pkt, iface=interface, verbose=0)
   ```
   - Sends crafted ARP replies (op=2 = ARP reply)
   - Tells victim that gateway IP belongs to attacker's MAC
   - Tells gateway that victim IP belongs to attacker's MAC
   - Creates bidirectional traffic interception

3. **Continuous Poisoning Loop** (in `main()`)
   - Runs in background thread
   - Sends poisoning packets every `AttackConfig.ARP_POISON_INTERVAL` seconds
   - Maintains MITM position throughout attack

##### Phase 3: HTTP Packet Interception & Modification

4. **NetfilterQueue Setup** (`start_packet_injection()`)
   - Sets up iptables rule: `iptables -I FORWARD -j NFQUEUE --queue-num 0`
   - Redirects forwarded packets to userspace for processing
   - Binds packet processing function to queue

5. **Packet Analysis** (`modify_packet()`)
   ```python
   def modify_packet(packet):
       scapy_pkt = IP(packet.get_payload())
       
       if not (scapy_pkt.haslayer(Raw) and scapy_pkt.haslayer(TCP)):
           packet.accept()
           return
   ```
   - Filters for TCP packets with payload data
   - Only processes HTTP traffic

6. **HTTP Detection & Parsing**
   ```python
   if b"HTTP/" not in payload or b"Content-Type: text/html" not in payload:
       packet.accept()
       return
   ```
   - Identifies HTTP responses containing HTML content
   - Splits HTTP headers from body content

7. **Content Encoding Handling**
   - **Gzip Compression**: Detects and decompresses gzipped content
   - **Chunked Transfer**: Handles HTTP chunked encoding
   - **Header Analysis**: Parses HTTP headers for encoding information

8. **HTML Injection Process**
   ```python
   def inject_at_top(html_bytes, injection_code):
       pattern = re.compile(b"(<body[^>]*>)", re.IGNORECASE)
       match = pattern.search(html_bytes)
       if match:
           insert_pos = match.end()
           return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
   ```
   - Locates `<body>` tag in HTML content
   - Injects payload from `AttackConfig.INJECTION_PAYLOADS`
   - Falls back to prepending if no body tag found

9. **Packet Reconstruction**
   - Updates Content-Length header for modified content
   - Recompresses content if originally gzipped
   - Re-encodes as chunked if originally chunked
   - Clears checksums to force recalculation
   - Forwards modified packet to destination

##### Phase 4: Cleanup & Restoration

10. **Graceful Exit** (`exit_gracefully()`)
    - Triggered by Ctrl+C (SIGINT)
    - Restores correct ARP entries using `arp_restore.py`
    - Disables IP forwarding
    - Clears iptables rules

### 2. Alternative Injection (`http_injection_mitmproxy.py`)

Uses mitmproxy framework for cleaner HTTP manipulation:
- Automatically handles encoding/decoding
- Simpler content modification
- Better suited for complex HTTP scenarios

### 3. ARP Restoration (`arp_restore.py`)

Standalone utility to restore ARP tables:
- Imports configuration from `config.py`
- Sends correct ARP replies to both victim and gateway
- Repairs network connectivity after attack
- Can be used for emergency cleanup
- Accepts command-line parameters or uses config defaults

### 4. Network Discovery (`network_device_scanner.py`)

Comprehensive utility for network reconnaissance and device identification:
- Uses configuration for default interface and network range
- Supports single IP lookup or network range scanning
- MAC address discovery with vendor identification
- Device type detection and categorization
- Command-line interface with multiple options
- Essential for configuring attack parameters
- Helps identify active devices on network

#### Usage Examples:
```bash
# Scan entire network with device identification
python3 network_device_scanner.py

# Scan with detailed nmap information
python3 network_device_scanner.py --detailed

# Look up specific IP with MAC resolution
python3 network_device_scanner.py --resolve 192.168.0.1

# Use custom interface
python3 network_device_scanner.py -i eth0

# Save results for configuration
python3 network_device_scanner.py --save network_scan.json
```

## Attack Flow Summary

1. **Configuration**: Load settings from `config.py` and user overrides
2. **Reconnaissance**: Use `network_device_scanner.py` to discover target MAC addresses and device information
3. **System Preparation**: Enable IP forwarding
4. **ARP Poisoning**: Continuously poison ARP caches using config parameters
5. **Traffic Interception**: Capture forwarded packets using NetfilterQueue
6. **Content Modification**: Inject configured payloads into HTTP responses
7. **Packet Forwarding**: Send modified packets to destination
8. **Cleanup**: Restore ARP tables using `arp_restore.py` and system configuration

## Configuration Management

### Default Configuration
The system ships with safe defaults suitable for testing environments.

### User Customization
1. Copy `user_config_template.py` to `user_config.py`
2. Modify network-specific values
3. Tools automatically load custom settings

### Security Features
- Configuration validation
- Restricted network protection
- Automatic cleanup settings
- Legal compliance warnings

## Technical Components

### Dependencies
- **Scapy**: Packet crafting and manipulation
- **NetfilterQueue**: Linux packet interception
- **iptables**: Traffic redirection to userspace
- **Python libraries**: re, gzip, threading, signal

### Attack Capabilities
- Bidirectional traffic interception
- Real-time HTTP content modification
- Support for compressed content (gzip)
- Handling of chunked transfer encoding
- Graceful cleanup and restoration
- Configurable injection payloads

### Limitations
- Only works on same network segment (Layer 2)
- Requires root privileges for packet manipulation
- Limited to HTTP traffic (HTTPS is protected)
- Detectable by network monitoring tools
- ARP poisoning may trigger security alerts

## Security Implications

This code demonstrates several attack vectors:
- **ARP Spoofing**: Exploits ARP protocol's lack of authentication
- **MITM Attacks**: Complete traffic interception and modification
- **Content Injection**: Arbitrary HTML/JavaScript injection
- **Session Hijacking**: Potential for credential theft
- **Malware Distribution**: Injection of malicious scripts

## Ethical Considerations

This code should only be used for:
- Educational purposes in controlled environments
- Authorized penetration testing
- Network security research with proper permissions
- Demonstrating vulnerabilities to improve defenses

Unauthorized use constitutes a criminal offense in most jurisdictions. 