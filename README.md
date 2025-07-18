# ARP Cache Poisoning & MITM Attack Suite

A comprehensive educational toolkit for demonstrating ARP cache poisoning vulnerabilities and implementing defensive countermeasures. This project includes both offensive tools for security testing and defensive systems for protection.

## ⚠️ LEGAL DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This toolkit is designed for:
- Educational purposes in controlled environments
- Authorized penetration testing with written permission
- Network security research and vulnerability assessment
- Demonstrating security weaknesses to improve defenses

**Unauthorized use is illegal and may result in criminal charges.** Only use on networks you own or have explicit written permission to test.

## 🎯 Project Overview

This suite demonstrates:
- **ARP Protocol Vulnerabilities**: How lack of authentication enables spoofing
- **Man-in-the-Middle Attacks**: Real-time traffic interception and modification
- **HTTP Content Injection**: Dynamic payload insertion into web traffic
- **Defense Mechanisms**: Multiple layers of protection against ARP-based attacks
- **Network Discovery**: Comprehensive device identification and monitoring

## 📁 Project Structure

### Core Attack Tools
- **`http_interceptor.py`** - Main ARP poisoning and HTTP injection attack
- **`http_injection_mitmproxy.py`** - Alternative HTTP injection using mitmproxy framework
- **`arp_restore.py`** - ARP table restoration utility for cleanup

### Defense and Monitoring Tools
- **`arp_defense_monitor.py`** - Real-time ARP attack detection and countermeasures
- **`secure_arp_client.py`** - Secure ARP resolution with validation
- **`network_hardening_tools.py`** - System-level network protection
- **`network_device_scanner.py`** - Comprehensive network device discovery

### Configuration and Utilities
- **`config.py`** - Centralized configuration system
- **`user_config_template.py`** - Template for user-specific settings
- **`load_mac_database.py`** - MAC vendor database management

### Documentation
- **`CODE_FLOW_DOCUMENTATION.md`** - Detailed technical analysis
- **`PRACTICAL_TESTING_GUIDE.md`** - Step-by-step testing procedures

## 🔧 Configuration System

### Centralized Configuration
The project uses a sophisticated configuration system (`config.py`) that manages:

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

### User Customization

1. **Copy the template:**
   ```bash
   cp user_config_template.py user_config.py
   ```

2. **Edit your network-specific values:**
   ```python
   # Network Configuration
   NETWORK_INTERFACE = "wlp2s0"  # Your WiFi interface
   NETWORK_RANGE = "192.168.0.0/24"  # Your network range

   # Attack Target Configuration  
   VICTIM_IP = "192.168.0.105"
   VICTIM_MAC = "XX:XX:XX:XX:XX:XX"
   GATEWAY_IP = "192.168.0.1" 
   GATEWAY_MAC = "YY:YY:YY:YY:YY:YY"
   ```

3. **Tools automatically load your settings** when imported.

### Configuration Validation
```bash
# Test configuration validity
python3 config.py

# Check for errors
python3 -c "from config import validate_config; print(validate_config())"
```

## 🚀 Quick Start Guide

### 1. Installation

```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip iptables

# Install Python packages
pip3 install scapy netfilterqueue requests

# Optional: Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install scapy netfilterqueue requests
```

### 2. Initial Setup

```bash
# Test configuration system
python3 config.py

# Copy and customize configuration
cp user_config_template.py user_config.py
nano user_config.py  # Edit with your network details
```

### 3. Network Discovery

```bash
# Discover devices on your network
python3 network_device_scanner.py

# Scan with detailed information
python3 network_device_scanner.py --detailed

# Save results for later use
python3 network_device_scanner.py --save my_network.json
```

### 4. Attack Demonstration (Authorized Testing Only)

```bash
# Launch ARP poisoning attack (requires root)
sudo python3 http_interceptor.py

# Alternative: Use mitmproxy-based injection
sudo python3 http_injection_mitmproxy.py
```

### 5. Defense Testing

```bash
# Start ARP defense monitoring
sudo python3 arp_defense_monitor.py

# Enable secure ARP client
sudo python3 secure_arp_client.py

# Apply network hardening
sudo python3 network_hardening_tools.py --apply
```

## 🛡️ Defense Capabilities

### Real-time Monitoring (`arp_defense_monitor.py`)
- **ARP Table Monitoring**: Detects MAC address changes
- **Duplicate MAC Detection**: Identifies multiple IPs claiming same MAC
- **Trusted Device Validation**: Alerts when known devices are spoofed
- **Automatic Countermeasures**: Sends counter-ARP packets
- **Static ARP Management**: Sets permanent ARP entries

### Secure ARP Resolution (`secure_arp_client.py`)
- **Multi-validation**: Sends multiple ARP requests for consistency
- **Confidence Scoring**: Rates IP-MAC mappings based on validation
- **DNS Cross-validation**: Verifies mappings with DNS lookups
- **Blacklist Management**: Blocks suspicious MAC addresses
- **Gateway Protection**: Continuous monitoring of default gateway

### Network Hardening (`network_hardening_tools.py`)
- **Kernel ARP Filtering**: Enables OS-level protection
- **Firewall Rules**: iptables/ebtables configuration
- **Static ARP Tables**: Persistent ARP entry management
- **DHCP Snooping**: Monitors for rogue DHCP servers
- **Network Baseline**: Creates reference for normal activity

## 🔍 Network Discovery Features

### Device Scanner (`network_device_scanner.py`)
- **MAC Vendor Database**: Comprehensive manufacturer identification
- **Device Type Detection**: Intelligent categorization (laptops, phones, etc.)
- **Network Mapping**: Complete topology discovery
- **Enhanced Metadata**: Block types, registration info, update timestamps
- **Export/Import**: JSON format for data persistence

#### Usage Examples:
```bash
# Basic network scan
python3 network_device_scanner.py

# Detailed scan with nmap integration
python3 network_device_scanner.py --detailed

# Sort by device type or vendor
python3 network_device_scanner.py --sort type

# Monitor network changes
python3 network_device_scanner.py --monitor 60

# Use specific interface
python3 network_device_scanner.py -i eth0
```

## ⚙️ Attack Capabilities

### ARP Cache Poisoning (`http_interceptor.py`)
- **Bidirectional Poisoning**: Intercepts traffic in both directions
- **Automatic IP Forwarding**: Maintains network connectivity
- **Graceful Cleanup**: Restores ARP tables on exit
- **Configurable Timing**: Adjustable poison packet intervals

### HTTP Content Injection
- **Real-time Modification**: Injects content into HTTP responses
- **Encoding Support**: Handles gzip compression and chunked encoding
- **Multiple Payloads**: Pre-configured injection options
- **Smart Insertion**: Locates optimal injection points in HTML

#### Available Injection Payloads:
- `simple` - Basic HTML injection
- `alert` - JavaScript alert popup
- `image` - Visual overlay image
- `redirect` - Timed page redirection
- `demo` - Professional demonstration banner

### Alternative Implementation (`http_injection_mitmproxy.py`)
- **mitmproxy Framework**: More sophisticated HTTP handling
- **Automatic Encoding**: Built-in compression support
- **Transparent Proxy**: Seamless traffic interception

## 📊 Monitoring and Logging

### Comprehensive Logging
- **Attack Activities**: All actions logged to `attack.log`
- **Defense Events**: Monitoring results in `arp_defense.log`
- **Network Changes**: Device discovery in `network_monitor.log`
- **Configuration Changes**: Settings modifications tracked

### Real-time Alerts
- **Desktop Notifications**: Visual alerts for security events
- **Email Notifications**: Optional email alerting (configurable)
- **Console Output**: Real-time status and event reporting
- **Log File Integration**: Structured logging for analysis

## 🔐 Security Features

### Built-in Safety Measures
- **Configuration Validation**: Prevents common setup errors
- **Time Limits**: Automatic attack termination after set duration
- **Confirmation Prompts**: Requires user consent before attacks
- **Automatic Cleanup**: Restores network state on exit
- **Legal Warnings**: Displays compliance reminders

### Restricted Networks
The system refuses to attack certain network ranges:
- `10.0.0.0/8` (Private Class A)
- `172.16.0.0/12` (Private Class B)  
- `169.254.0.0/16` (Link-local)

### Audit Trail
- Complete activity logging
- Configuration change tracking
- Attack duration and target recording
- Cleanup action documentation

## 📚 Documentation

### Technical Documentation
- **`CODE_FLOW_DOCUMENTATION.md`** - In-depth code analysis and attack flow
- **`PRACTICAL_TESTING_GUIDE.md`** - Step-by-step testing procedures
- **Configuration comments** - Inline documentation in all files

### Educational Content
- ARP protocol vulnerability explanations
- MITM attack technique demonstrations
- Defense mechanism implementations
- Network security best practices

## 🔧 Troubleshooting

### Common Issues

#### Configuration Problems
```bash
# Check configuration validity
python3 config.py

# Verify network interface
ip link show wlp2s0

# Test user config loading  
python3 -c "from config import load_config_from_file; load_config_from_file()"
```

#### Permission Issues
```bash
# Ensure running as root for packet manipulation
sudo python3 http_interceptor.py

# Check file permissions
chmod +x *.py
```

#### Network Interface Issues
```bash
# List available interfaces
ip addr show

# Check interface status
iwconfig wlp2s0
```

#### Packet Interception Problems
```bash
# Verify iptables rules
sudo iptables -L -n

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Test NetfilterQueue
python3 -c "import netfilterqueue; print('OK')"
```

## 🎓 Educational Applications

### Learning Objectives
- Understand ARP protocol vulnerabilities
- Learn MITM attack techniques
- Explore network security monitoring
- Practice defensive countermeasures
- Study configuration management

### Laboratory Exercises
- Set up controlled attack scenarios
- Test detection capabilities
- Evaluate defense effectiveness
- Analyze network traffic patterns
- Configure security hardening

### Professional Development
- Penetration testing skill building
- Security monitoring experience
- Incident response training
- Network analysis capabilities
- Risk assessment techniques

## 🤝 Contributing

This project is designed for educational use. Contributions should focus on:
- Improving defensive capabilities
- Enhancing detection accuracy
- Adding safety features
- Expanding documentation
- Educational content development

## 📄 License

This project is provided for educational purposes. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse of this software.

## 🔗 Related Resources

- **NIST Cybersecurity Framework**
- **OWASP Testing Guide**
- **RFC 826 - ARP Specification**
- **Network Security Best Practices**
- **Ethical Hacking Guidelines**

---

**Remember**: The goal is to understand vulnerabilities to better defend against them, not to cause harm or unauthorized access. Always obtain proper authorization before testing network security tools. 