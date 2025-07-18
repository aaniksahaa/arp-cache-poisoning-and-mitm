# Practical Testing Guide: ARP Cache Poisoning & MITM Attack

## ⚠️ LEGAL DISCLAIMER
This guide is for educational purposes only. Only test on networks you own or have explicit written permission to test. Unauthorized network attacks are illegal and may result in criminal charges.

## Prerequisites

### Hardware Requirements
- **3 Devices minimum**:
  - Attacker laptop (Ubuntu with Python)
  - Victim laptop (Ubuntu or any OS)
  - WiFi router/access point
- All devices on same WiFi network
- Physical access to attacker machine

### Software Requirements (Attacker Machine)
```bash
# Install required packages
sudo apt update
sudo apt install python3 python3-pip iptables

# Install Python dependencies
pip3 install scapy netfilterqueue

# Alternative: Install in virtual environment
python3 -m venv venv
source venv/bin/activate
pip install scapy netfilterqueue
```

## Step-by-Step Testing Procedure

### Phase 1: Configuration Setup

#### 1.1 Initial Configuration
```bash
# Test the configuration system
python3 config.py

# Copy the template for customization
cp user_config_template.py user_config.py

# Edit your network-specific settings
nano user_config.py
```

#### 1.2 Network Configuration Template
Edit `user_config.py` with your network details:
```python
# Network Configuration
NETWORK_INTERFACE = "wlp2s0"  # Your WiFi interface
NETWORK_RANGE = "192.168.0.0/24"  # Your network range

# Attack Target Configuration
VICTIM_IP = "192.168.0.105"      # Target laptop IP
VICTIM_MAC = "XX:XX:XX:XX:XX:XX" # Target laptop MAC
GATEWAY_IP = "192.168.0.1"       # Router IP
GATEWAY_MAC = "YY:YY:YY:YY:YY:YY" # Router MAC

# Safety settings
REQUIRE_CONFIRMATION = True
MAX_ATTACK_DURATION = 1800  # 30 minutes
```

### Phase 2: Network Reconnaissance

#### 2.1 Identify Network Configuration
```bash
# Find your network interface
ip addr show
# or
iwconfig

# Find network range
ip route | grep wlp2s0  # Replace with your interface
```

#### 2.2 Discover Active Devices
```bash
# Use the comprehensive device scanner
python3 network_device_scanner.py

# Scan with detailed device identification
python3 network_device_scanner.py --detailed

# Scan specific network range
python3 network_device_scanner.py --network 192.168.0.0/24

# Sort results by device type or vendor
python3 network_device_scanner.py --sort type
```

#### 2.3 Get Target MAC Addresses
```bash
# Scan for all devices with device identification
python3 network_device_scanner.py -i wlp2s0

# Save results for later reference
python3 network_device_scanner.py --save network_discovery.json

# Load previous scan results
python3 network_device_scanner.py --load network_discovery.json
```

#### 2.4 Update Configuration
Update your `user_config.py` with discovered MAC addresses:
```python
VICTIM_MAC = "24:b2:b9:3e:22:13"  # From discovery scan
GATEWAY_MAC = "60:a4:b7:a9:77:05" # From discovery scan
```

### Phase 3: Attack Execution

#### 3.1 Pre-Attack Testing
```bash
# Verify configuration
python3 config.py

# Test connectivity
ping 192.168.0.105  # Should reach victim
ping 192.168.0.1    # Should reach gateway

# Check current ARP table
arp -a
```

#### 3.2 Launch Attack
```bash
# Run the main attack script (requires root)
sudo python3 http_interceptor.py

# Expected output:
# [*] Starting ARP poisoning & MITM attack
# [*] HTTP injector running... Press Ctrl+C to stop.
```

#### 3.3 Monitor Attack Progress
Open another terminal to monitor:
```bash
# Watch ARP table changes on victim (if accessible)
watch -n 1 "arp -a"

# Monitor network traffic
sudo tcpdump -i wlp2s0 arp

# Check iptables rules
sudo iptables -L -n
```

### Phase 4: Victim Testing

#### 4.1 Victim Machine Setup
On the victim laptop:
```bash
# Clear ARP cache (optional)
sudo ip neigh flush all

# Note current gateway MAC
arp -a | grep 192.168.0.1
```

#### 4.2 Test HTTP Traffic
On victim machine, visit HTTP websites:
```bash
# Use browsers or command line
curl http://httpforever.com
curl http://example.com
wget http://httpforever.com -O -

# Or open Firefox/Chrome and browse:
# - http://neverssl.com
# - http://httpforever.com
# - Any non-HTTPS website
```

#### 4.3 Verify Attack Success
**Signs of successful attack:**
- Injected content appears on web pages (red banner at top)
- Gateway MAC address in ARP table changes to attacker's MAC
- Modified content visible in HTTP responses

### Phase 5: Advanced Testing Scenarios

#### 5.1 Test Different Injection Payloads
Modify `user_config.py` to test different payloads:
```python
# In user_config.py, add:
CUSTOM_INJECTION = b"<h1 style='color:blue;'>CUSTOM PAYLOAD TEST</h1>"
```

Then update the attack script to use:
```python
# In config.py, modify CURRENT_PAYLOAD
CURRENT_PAYLOAD = 'simple'  # or 'alert', 'image', 'redirect'
```

#### 5.2 Test Against Different Websites
- **HTTP-only sites**: httpforever.com, neverssl.com
- **Mixed content sites**: Sites with HTTP resources
- **Local web servers**: Set up Apache/Nginx for testing

#### 5.3 Test Encoding Scenarios
Configure a local web server with:
- Gzip compression enabled
- Chunked transfer encoding
- Different content types

### Phase 6: Cleanup and Recovery

#### 6.1 Stop Attack
```bash
# Press Ctrl+C in attack terminal
# Script should automatically:
# - Restore ARP tables
# - Disable IP forwarding
# - Clear iptables rules
```

#### 6.2 Manual Cleanup (if needed)
```bash
# Use the dedicated restore script
sudo python3 arp_restore.py

# Clear iptables rules
sudo iptables -F
sudo iptables -X

# Disable IP forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward

# Clear ARP cache on all machines
sudo ip neigh flush all
```

#### 6.3 Verify Recovery
```bash
# Check ARP table restoration
arp -a

# Test normal connectivity
ping google.com
curl https://google.com
```

## Configuration Management

### Default Settings
The tools ship with safe defaults in `config.py`:
- 30-minute maximum attack duration
- Confirmation required before attacks
- Automatic cleanup enabled
- Legal warnings displayed

### Customization Options
1. **Network Settings**: Interface, IP ranges, timeouts
2. **Attack Parameters**: Target IPs, injection payloads
3. **Safety Features**: Duration limits, confirmation prompts
4. **Logging**: Attack activity logging, audit trails

### Configuration Validation
```bash
# Test configuration validity
python3 config.py

# Check for common configuration errors
python3 -c "from config import validate_config; print(validate_config())"
```

## Troubleshooting Common Issues

### Issue 1: Configuration Errors
```bash
# Check configuration validity
python3 config.py

# Verify network interface exists
ip link show wlp2s0

# Test user config loading
python3 -c "from config import load_config_from_file; load_config_from_file()"
```

### Issue 2: Permission Denied
```bash
# Ensure running as root
sudo python3 http_interceptor.py

# Check file permissions
chmod +x *.py
```

### Issue 3: No Packet Interception
```bash
# Check iptables rules
sudo iptables -L -n

# Verify IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Check NetfilterQueue installation
python3 -c "import netfilterqueue; print('OK')"
```

### Issue 4: ARP Poisoning Not Working
```bash
# Check if ARP entries are changing
arp -a

# Verify network interface
ip addr show

# Test manual MAC discovery
python3 network_device_scanner.py --resolve 192.168.0.1
```

### Issue 5: No HTTP Injection
```bash
# Test with simple HTTP site
curl -v http://httpforever.com

# Check configuration
python3 config.py

# Verify injection payload syntax
python3 -c "from config import AttackConfig; print(AttackConfig.INJECTION_CODE)"
```

## Attack Demonstration Ideas

### Scenario 1: Content Replacement Demo
- Use the 'demo' payload (red banner)
- Demonstrate professional security testing
- Show traffic interception capabilities

### Scenario 2: Custom Payload Testing
- Create custom injection in `user_config.py`
- Test different HTML/JavaScript payloads
- Demonstrate various attack vectors

### Scenario 3: Network Monitoring
- Run defense tools alongside attack
- Show detection capabilities
- Demonstrate monitoring effectiveness

### Scenario 4: Recovery Testing
- Test automatic cleanup on Ctrl+C
- Verify manual restoration with `arp_restore.py`
- Show network recovery procedures

## Security Features

### Built-in Safety Measures
- **Configuration validation**: Prevents common mistakes
- **Time limits**: Automatic attack termination
- **Confirmation prompts**: Require user consent
- **Automatic cleanup**: Restore network state on exit
- **Legal warnings**: Remind users of responsibilities

### Audit Trail
- All activities logged to `attack.log`
- Configuration changes tracked
- Attack duration and targets recorded
- Cleanup actions documented

## Educational Value

This exercise demonstrates:
- **ARP Protocol Vulnerabilities**: Lack of authentication
- **Layer 2 Attack Vectors**: Network-level manipulation
- **HTTP Insecurity**: Plaintext transmission risks
- **MITM Attack Techniques**: Traffic interception and modification
- **Configuration Management**: Centralized security tool configuration
- **Defense Importance**: Need for encryption and monitoring

## Legal and Ethical Guidelines

### Authorized Testing Only
- Obtain written permission before testing
- Use only on networks you own or control
- Document testing scope and limitations
- Ensure no impact on production systems

### Configuration Security
- Keep user configuration files secure
- Don't commit sensitive network information
- Use configuration templates for sharing
- Review settings before each test

### Professional Use
- Conduct only within penetration testing scope
- Follow responsible disclosure principles
- Document findings and recommendations
- Provide remediation guidance

Remember: The goal is to understand vulnerabilities to better defend against them, not to cause harm or unauthorized access. 