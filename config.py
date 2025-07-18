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
    def __init__(self, name, ip, mac, device_type="unknown", description=""):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.device_type = device_type  # laptop, phone, tablet, router, etc.
        self.description = description
        
    def __str__(self):
        return f"{self.name} ({self.ip}) - {self.device_type}"
    
    def __repr__(self):
        return f"Device('{self.name}', '{self.ip}', '{self.mac}', '{self.device_type}')"

# ==========================================
# NETWORK CONFIGURATION
# ==========================================

class NetworkConfig:
    """Basic network configuration"""
    
    # Network interface (automatically detect or specify)
    INTERFACE = "wlp2s0"  # Change this to your network interface
    
    # Network range for scanning
    NETWORK_RANGE = "192.168.0.0/24"  # Adjust to your network
    
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
    laptop = Device(
        name="laptop",
        ip="192.168.0.125",
        mac="24:b2:b9:3e:22:13",
        device_type="laptop",
        description="Lenovo LOQ Laptop"
    )
    
    phone = Device(
        name="phone", 
        ip="192.168.0.201",
        mac="f4:30:8b:91:d6:1f",
        device_type="phone",
        description="Xiaomi Redmi Note 10"
    )
    
    gateway = Device(
        name="gateway",
        ip="192.168.0.1",
        mac="60:a4:b7:a9:77:05", 
        device_type="router",
        description="WiFi Router/Gateway"
    )
    
    # Add more devices as needed
    # desktop = Device("desktop", "192.168.0.XXX", "XX:XX:XX:XX:XX:XX", "desktop")
    
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
    
    # ===== BIDIRECTIONAL ATTACK TARGETS =====
    
    # Target 1: Primary device to intercept
    POISON_TARGET_1 = DeviceRegistry.laptop  # Change this to your target device
    
    # Target 2: Secondary device to intercept  
    POISON_TARGET_2 = DeviceRegistry.phone   # Change this to your target device
    
    # Gateway device (router)
    GATEWAY_DEVICE = DeviceRegistry.gateway
    
    # ===== BACKWARDS COMPATIBILITY =====
    # Keep old variable names for existing scripts
    @property
    def VICTIM_IP(self):
        return self.POISON_TARGET_1.ip
    
    @property 
    def VICTIM_MAC(self):
        return self.POISON_TARGET_1.mac
        
    @property
    def GATEWAY_IP(self):
        return self.GATEWAY_DEVICE.ip
        
    @property
    def GATEWAY_MAC(self):
        return self.GATEWAY_DEVICE.mac
    
    # Attack timing
    ARP_POISON_INTERVAL = 2  # seconds between ARP poison packets
    
    # Socket interception configuration
    SOCKET_PORTS = [9999, 8080, 12345, 22, 23, 21]  # Ports to intercept
    ENABLE_BIDIRECTIONAL_INTERCEPTION = True
    
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
        'update':   'REBOOT'
    }

    
    # HTTP Injection Configuration (for backward compatibility)
    INJECTION_CODE = b"""
    <div style='position:fixed;top:0;left:0;width:100%;background:red;color:white;
    text-align:center;padding:10px;z-index:9999;font-size:18px;'>
    NETWORK SECURITY DEMONSTRATION - TRAFFIC INTERCEPTED
    </div>
    """
    
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

# Create instance for backward compatibility
AttackConfig = AttackConfig()

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
    SCAN_RESULTS_FILE = "network_scan_results.json"

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
    if not AttackConfig.POISON_TARGET_1:
        errors.append("POISON_TARGET_1 not configured")
    if not AttackConfig.POISON_TARGET_2: 
        errors.append("POISON_TARGET_2 not configured")
    if not AttackConfig.GATEWAY_DEVICE:
        errors.append("GATEWAY_DEVICE not configured")
    
    # Check if targets are the same
    if (AttackConfig.POISON_TARGET_1 and AttackConfig.POISON_TARGET_2 and
        AttackConfig.POISON_TARGET_1.ip == AttackConfig.POISON_TARGET_2.ip):
        warnings.append("POISON_TARGET_1 and POISON_TARGET_2 have the same IP")
    
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
    print(f"  Target 1: {AttackConfig.POISON_TARGET_1}")
    print(f"  Target 2: {AttackConfig.POISON_TARGET_2}")
    print(f"  Gateway: {AttackConfig.GATEWAY_DEVICE}")
    
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
NetworkConfig.NETWORK_RANGE = "192.168.0.0/24"  # Change to your network

# ==========================================
# DEVICE REGISTRY
# ==========================================

# Define your actual devices here
DeviceRegistry.laptop = Device(
    name="ubuntu_server",
    ip="192.168.0.105",           # Replace with actual IP
    mac="XX:XX:XX:XX:XX:XX",      # Replace with actual MAC
    device_type="laptop",
    description="Ubuntu Server Laptop"
)

DeviceRegistry.phone = Device(
    name="windows_client", 
    ip="192.168.0.150",           # Replace with actual IP
    mac="YY:YY:YY:YY:YY:YY",      # Replace with actual MAC
    device_type="laptop",
    description="Windows Client Laptop"
)

DeviceRegistry.gateway = Device(
    name="router",
    ip="192.168.0.1",             # Replace with actual router IP
    mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",      # Replace with actual router MAC
    device_type="router",
    description="WiFi Router"
)

# ==========================================
# ATTACK CONFIGURATION
# ==========================================

# Set your attack targets (which devices to intercept between)
AttackConfig.POISON_TARGET_1 = DeviceRegistry.laptop  # Server
AttackConfig.POISON_TARGET_2 = DeviceRegistry.phone   # Client
AttackConfig.GATEWAY_DEVICE = DeviceRegistry.gateway

# Custom socket modifications (what to replace in messages)
AttackConfig.SOCKET_MODIFICATIONS = {
    'hello': 'Bye',
    'hi': 'OK',
    'secret': 'HACK',
    'password': 'PWNED'
}

# Ports to monitor for socket communication
AttackConfig.SOCKET_PORTS = [9999, 8080, 12345]

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