# DNS Interception & Manipulation Guide

## Overview

DNS (Domain Name System) interception is a powerful MITM attack technique that allows you to:

1. **Redirect domain requests** - Change what site users actually visit (e.g., youtube.com → google.com)
2. **Poison DNS responses** - Change IP addresses to redirect traffic to your attack server
3. **Monitor DNS queries** - See what domains users are trying to access

## DNS Attack Types Implemented

### 1. DNS Request Modification
**What it does**: Intercepts DNS queries and changes the requested domain before forwarding.

**Example**: User wants to visit `youtube.com`, but the query is changed to `google.com`.

**Use cases**:
- Content filtering/blocking
- Redirecting social media to educational sites
- Phishing redirections

### 2. DNS Response Modification  
**What it does**: Intercepts DNS responses and changes the IP addresses before sending to the client.

**Example**: User queries `google.com`, gets response pointing to your attack server IP `192.168.1.100`.

**Use cases**:
- Redirect traffic to fake websites
- Capture credentials on login pages
- Serve malicious content

## Files Created

### 1. `dns_interceptor.py` - Main DNS Attack Tool
This is the comprehensive DNS interceptor that integrates with your existing ARP poisoning setup.

**Features**:
- ✅ Bidirectional ARP poisoning 
- ✅ DNS request modification (domain redirections)
- ✅ DNS response modification (IP changes)
- ✅ Detailed logging
- ✅ Configurable targets and redirections
- ✅ Automatic cleanup

### 2. `dns_test_script.py` - DNS Analysis & Testing Tool  
A learning tool to understand DNS packets and test spoofing concepts.

**Features**:
- 🔍 Monitor live DNS traffic
- 🧪 Test DNS queries  
- 🎭 Demonstrate DNS spoofing
- 📊 Analyze DNS packet structure

## Quick Start

### 1. Configure Your Targets
Edit the configuration in `dns_interceptor.py`:

```python
# Set your attack server IP
DNS_ATTACK_IP = "192.168.1.100"  # Change this to your IP

# Configure domain redirections (request modification)
DNS_DOMAIN_REDIRECTIONS = {
    'youtube.com': 'google.com',
    'facebook.com': 'google.com',
    'instagram.com': 'google.com',
}

# Configure IP redirections (response modification)  
DNS_IP_REDIRECTIONS = {
    'google.com': DNS_ATTACK_IP,
    'youtube.com': DNS_ATTACK_IP,
    'facebook.com': DNS_ATTACK_IP,
}
```

### 2. Set Target Devices
Make sure your `config.py` has the correct target devices:

```python
# In config.py, update DeviceRegistry
laptop = Device("192.168.1.100", "aa:bb:cc:dd:ee:ff", "laptop")
phone = Device("192.168.1.200", "11:22:33:44:55:66", "phone")
```

### 3. Run DNS Interception Attack

```bash
# Basic DNS interception attack
sudo python3 dns_interceptor.py

# Monitor DNS traffic (learning tool)
sudo python3 dns_test_script.py monitor

# Test DNS query for a domain
python3 dns_test_script.py query youtube.com

# Demonstrate DNS spoofing concepts
python3 dns_test_script.py demo
```

## Configuration Options

### DNS Attack Settings

```python
# Enable/disable attack types
ENABLE_DNS_REQUEST_MODIFICATION = True   # Domain redirections
ENABLE_DNS_RESPONSE_MODIFICATION = True  # IP redirections

# Your attack server IP
DNS_ATTACK_IP = "192.168.1.100"
```

### Domain Redirections (Request Modification)

```python
DNS_DOMAIN_REDIRECTIONS = {
    'youtube.com': 'google.com',       # Redirect YouTube to Google
    'facebook.com': 'wikipedia.org',   # Redirect Facebook to Wikipedia  
    'tiktok.com': 'google.com',        # Block TikTok by redirecting
    'instagram.com': 'google.com',     # Redirect Instagram
}
```

### IP Redirections (Response Modification)

```python
DNS_IP_REDIRECTIONS = {
    'google.com': '192.168.1.100',     # Redirect Google to your server
    'youtube.com': '192.168.1.100',    # Redirect YouTube to your server
    'facebook.com': '192.168.1.100',   # Redirect Facebook to your server
    'github.com': '192.168.1.100',     # Redirect GitHub to your server
}
```

## Attack Scenarios

### Scenario 1: Social Media Blocking
**Goal**: Redirect social media sites to educational content.

```python
DNS_DOMAIN_REDIRECTIONS = {
    'youtube.com': 'khanacademy.org',
    'facebook.com': 'wikipedia.org', 
    'instagram.com': 'coursera.org',
    'tiktok.com': 'edx.org',
}
```

### Scenario 2: Credential Harvesting
**Goal**: Redirect login pages to fake sites that capture credentials.

```python
DNS_IP_REDIRECTIONS = {
    'gmail.com': '192.168.1.100',       # Your fake Gmail login
    'facebook.com': '192.168.1.100',    # Your fake Facebook login
    'github.com': '192.168.1.100',      # Your fake GitHub login
}
```

### Scenario 3: Content Injection  
**Goal**: Serve modified versions of websites with injected content.

```python
DNS_IP_REDIRECTIONS = {
    'news.com': '192.168.1.100',        # Your modified news site
    'weather.com': '192.168.1.100',     # Your weather site with ads
}
```

## Testing & Verification

### 1. Monitor DNS Traffic
```bash
# See all DNS queries in real-time
sudo python3 dns_test_script.py monitor
```

### 2. Test Individual Queries
```bash
# Test how your attack affects specific domains
python3 dns_test_script.py query youtube.com
python3 dns_test_script.py query google.com
python3 dns_test_script.py query facebook.com
```

### 3. Verify Attack is Working
After starting the attack, on the target device:

```bash
# Check if DNS resolution is changed
nslookup youtube.com
dig google.com

# Check if traffic is redirected  
curl -I http://youtube.com
ping google.com
```

## How It Works

### 1. ARP Poisoning Setup
```
[Target Device] ←→ [Attacker] ←→ [Router]
```
- Target thinks attacker is the router
- Router thinks attacker is the target
- All traffic flows through attacker

### 2. DNS Interception
```
Target → DNS Query (youtube.com) → Attacker → Modified Query (google.com) → DNS Server
Target ← DNS Response (google IP) ← Attacker ← DNS Response ← DNS Server
```

### 3. Traffic Flow
```
1. Target sends DNS query for youtube.com
2. Attacker intercepts query  
3. Attacker modifies query to google.com (request modification)
   OR
   Attacker forwards query and modifies response (response modification)
4. Target receives modified DNS response
5. Target connects to wrong IP/domain
```

## Advanced Techniques

### 1. Conditional Redirections
Modify the code to redirect based on conditions:

```python
def modify_dns_request(scapy_pkt):
    # Only redirect during work hours
    from datetime import datetime
    if 9 <= datetime.now().hour <= 17:
        # Apply redirections
        pass
```

### 2. Logging User Activity
Track what domains users visit:

```python
def log_dns_activity(domain, user_ip):
    with open('dns_activity.log', 'a') as f:
        f.write(f"{datetime.now()}: {user_ip} -> {domain}\n")
```

### 3. Dynamic IP Selection
Change redirect IPs based on domain:

```python
def get_attack_ip(domain):
    if 'social' in domain:
        return '192.168.1.100'  # Social media server
    elif 'news' in domain:
        return '192.168.1.101'  # News server
    else:
        return '192.168.1.102'  # Default server
```

## Troubleshooting

### Common Issues

1. **No DNS packets intercepted**
   - Check iptables rules: `iptables -L -n`
   - Verify ARP poisoning is working
   - Ensure targets are configured correctly

2. **DNS modifications not applied**
   - Check domain matching (case sensitive)
   - Verify checksum recalculation 
   - Look at debug logs

3. **Target can't browse internet**
   - Check IP forwarding: `cat /proc/sys/net/ipv4/ip_forward`
   - Verify iptables rules don't block traffic
   - Check DNS server reachability

### Debug Commands

```bash
# Check iptables rules
sudo iptables -L -n -v

# Monitor network traffic
sudo tcpdump -i any -n port 53

# Check ARP tables
arp -a

# Test DNS resolution
nslookup google.com
dig youtube.com
```

## Security Considerations

⚠️ **Important**: These tools are for educational and authorized security testing only.

### Legal Use Only
- Only use on networks you own or have explicit permission to test
- Always restore network settings after testing
- Document all testing activities

### Cleanup
The script automatically cleans up on exit (Ctrl+C), but you can also manually:

```bash
# Restore IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Clear iptables rules  
iptables -F

# Restore ARP tables
python3 arp_restore.py
```

## Extending the System

### Add New Attack Types
1. **DNS Cache Poisoning**: Inject long-lived fake DNS entries
2. **DNSSEC Bypass**: Handle DNSSEC-protected domains  
3. **DoH/DoT Interception**: Intercept DNS-over-HTTPS/TLS
4. **Wildcard Redirections**: Redirect entire TLDs (*.com)

### Integration Ideas  
1. **Web Server**: Set up fake websites for redirected domains
2. **SSL Certificates**: Generate fake certificates for HTTPS sites
3. **Traffic Analysis**: Analyze and log all intercepted traffic
4. **Real-time Dashboard**: Web interface showing live DNS activity

This guide provides everything needed to understand and implement DNS interception attacks as part of your MITM toolkit! 