# 🛡️ Unified ARP Spoofing & MITM Attack System

A comprehensive, user-friendly interface for performing various ARP spoofing and Man-in-the-Middle (MITM) attacks with automatic device discovery and configuration.

## ✨ Features

### 🔄 **Fully Automated Workflow**
- **Network Discovery**: Automatically scans and identifies all devices on the network
- **Device Selection**: Interactive device selection with detailed information display
- **Attack Configuration**: Automatic configuration based on selected devices and attack type
- **Attack Execution**: One-click attack execution with proper cleanup

### 🎯 **7 Attack Types Supported**

#### HTTP Attacks
1. **HTTP Traffic Monitoring** 👁️ - Monitor and log HTTP traffic without modification
2. **HTTP Content Injection** 🔧 - Inject malicious content into HTTP responses  
3. **HTTP Traffic Blocking** 🚫 - Block all HTTP traffic (DoS attack)

#### TCP Attacks
4. **TCP Socket Monitoring** 👀 - Monitor TCP communications between two devices
5. **TCP Message Tampering** ✂️ - Intercept and modify TCP messages between devices
6. **TCP Communication Blocking** ❌ - Block TCP communications between devices

#### DNS Attacks
7. **DNS Query Interception** 🌐 - Intercept and redirect DNS queries

### 🔧 **Modular Architecture**
- **Common ARP Poisoning**: Centralized ARP poisoning for all attack types
- **Device Scanner**: Enhanced network scanning with device type detection
- **Attack Manager**: Unified attack configuration and execution
- **Utility Functions**: Common UI and validation functions

## 📁 File Structure

```
├── main.py                          # Main entry point - run this!
├── device_scanner.py                # Network device discovery and selection
├── attack_manager.py                # Attack type management and execution
├── common/                          # Shared modules
│   ├── __init__.py
│   ├── utils.py                     # Common utility functions
│   └── arp_poison.py               # Modular ARP poisoning component
├── scanner.py                       # Original scanner (used internally)
├── config.py                        # Configuration file (auto-updated)
├── http_interceptor.py             # HTTP attack implementation
├── dns_interceptor.py              # DNS attack implementation
├── bidirectional_tcp_interceptor.py # TCP attack implementation
├── requirements.txt                 # Python dependencies
└── README_UNIFIED.md               # This file
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Unified System
```bash
sudo python3 main.py
```

### 3. Follow the Interactive Workflow

#### Step 1: Network Device Discovery
The system automatically scans your network and displays all discovered devices with:
- Device type (laptop, phone, router, etc.)
- IP address and MAC address
- Hostname and vendor information
- Device icons for easy identification

#### Step 2: Attack Type Selection
Choose from 7 available attack types:
```
[1] 👁️ HTTP Traffic Monitoring - Monitor HTTP traffic without modification
[2] 🔧 HTTP Content Injection - Inject malicious content into HTTP responses  
[3] 🚫 HTTP Traffic Blocking - Block all HTTP traffic (DoS attack)
[4] 👀 TCP Socket Monitoring - Monitor TCP communications between devices
[5] ✂️ TCP Message Tampering - Intercept and modify TCP messages
[6] ❌ TCP Communication Blocking - Block TCP communications
[7] 🌐 DNS Query Interception - Intercept and redirect DNS queries
```

#### Step 3: Device Role Assignment
Based on your attack type, select devices for specific roles:

**HTTP Attacks require:**
- **Victim**: Target device whose HTTP traffic will be intercepted
- **Gateway**: Router or server device

**TCP Attacks require:**
- **Device 1**: First device in the communication pair
- **Device 2**: Second device in the communication pair  
- **Gateway**: Router for routing traffic

**DNS Attacks require:**
- **Target 1**: First target device
- **Target 2**: Second target device
- **Gateway**: Router device

#### Step 4: Attack Execution
The system automatically:
- Configures all settings
- Enables IP forwarding
- Sets up ARP poisoning
- Starts the appropriate interceptor
- Provides real-time attack feedback

## 💡 Usage Examples

### Example 1: Monitor HTTP Traffic
1. Run `sudo python3 main.py`
2. Select "HTTP Traffic Monitoring"
3. Choose victim device (e.g., a phone)
4. Choose gateway device (e.g., your router)  
5. Watch HTTP requests and responses in real-time

### Example 2: TCP Message Tampering
1. Run `sudo python3 main.py`
2. Select "TCP Message Tampering"
3. Choose two devices that communicate via TCP
4. Choose gateway device
5. Messages like "hello" will be changed to "HACK!" in real-time

### Example 3: DNS Redirection
1. Run `sudo python3 main.py`
2. Select "DNS Query Interception"  
3. Choose target devices and gateway
4. DNS queries for sites like YouTube will be redirected to Google

## 🔧 Configuration

The system automatically updates `config.py` based on your device selections. You can also manually modify:

- **HTTP_ATTACK_MODE**: "MONITOR", "TAMPER", or "DROP"
- **TCP_ATTACK_MODE**: "MONITOR", "TAMPER", or "DROP"  
- **SOCKET_MODIFICATIONS**: Dictionary of TCP message replacements
- **INJECTION_CODE**: HTML code injected into web pages

## 🛡️ Security Notes

**⚠️ IMPORTANT**: This tool is for educational and authorized security testing only.

- Always obtain proper authorization before testing
- Only use on networks you own or have explicit permission to test
- Clean shutdown (Ctrl+C) properly restores ARP tables
- Monitor network traffic to ensure attacks are working as expected

## 🐛 Troubleshooting

### Common Issues

1. **"Permission denied" errors**
   ```bash
   sudo python3 main.py  # Run as root
   ```

2. **No devices found during scan**
   - Check your network interface in `config.py`
   - Ensure you're on the same network as target devices
   - Some devices may not respond to ARP requests

3. **ARP poisoning not working**
   - Verify devices are selected correctly
   - Check that MAC addresses were discovered
   - Some modern devices have ARP spoofing protection

4. **Attacks not intercepting traffic**
   - Ensure IP forwarding is enabled (automatic)
   - Check iptables rules (automatic)
   - Verify target devices are generating the expected traffic

### Debug Mode
Enable debug logging by modifying the logging level in attack modules:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 🔄 Migration from Old System

If you were using the old manual system:

### Old Process:
1. Run `python3 scanner.py`
2. Manually copy IPs and MACs
3. Edit `config.py` with device information
4. Run specific interceptor (e.g., `python3 http_interceptor.py`)

### New Process:
1. Run `sudo python3 main.py`
2. Select attack type
3. Select devices from the UI
4. Attack starts automatically

The old individual scripts still work but are no longer needed for most use cases.

## 📊 Features Comparison

| Feature | Old System | New Unified System |
|---------|------------|-------------------|
| Device Discovery | Manual scan + copy/paste | Automatic with selection UI |
| Configuration | Manual config.py editing | Automatic based on selections |
| Attack Types | 3 separate scripts | 7 types in one interface |
| User Experience | Command-line expert | Beginner-friendly GUI |
| Error Handling | Basic | Comprehensive validation |
| Cleanup | Manual | Automatic on exit |

## 🎯 Advanced Usage

### Custom Device Roles
You can modify `attack_manager.py` to add custom device role requirements for specific attack scenarios.

### New Attack Types
To add new attack types:

1. Add to `AttackType` enum in `attack_manager.py`
2. Add configuration in `attack_configs` dictionary
3. Implement execution method
4. Create or modify interceptor script

### Network Interface Selection
The system auto-detects your network interface, but you can override in `config.py`:
```python
INTERFACE = "wlp2s0"  # Your specific interface
```
