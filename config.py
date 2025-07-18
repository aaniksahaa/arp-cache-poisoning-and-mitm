#!/usr/bin/env python3
"""
Configuration File for ARP Cache Poisoning & MITM Tools
Centralized configuration for attack, defense, and network discovery tools
"""

import os
from datetime import datetime

# ==========================================
# NETWORK CONFIGURATION
# ==========================================

class NetworkConfig:
    """Network interface and IP configuration"""
    
    # Default network interface (change based on your system)
    # Use 'ip addr show' or 'iwconfig' to find your interface
    INTERFACE = "wlp2s0"
    
    # Network range for scanning (auto-detected if None)
    NETWORK_RANGE = "192.168.0.0/24"
    
    # Timeout settings
    PING_TIMEOUT = 3        # seconds
    ARP_TIMEOUT = 2         # seconds
    NMAP_TIMEOUT = 30       # seconds
    HTTP_REQUEST_TIMEOUT = 5 # seconds

# ==========================================
# ATTACK CONFIGURATION
# ==========================================

class AttackConfig:
    """Configuration for ARP poisoning and MITM attacks"""
    
    # Target Configuration (CHANGE THESE FOR YOUR NETWORK)
    VICTIM_IP = "192.168.0.201"
    VICTIM_MAC = "f4:30:8b:91:d6:1f"
    
    # Router AP 
    GATEWAY_IP = "192.168.0.1"
    GATEWAY_MAC = "60:a4:b7:a9:77:05"

    # Lenovo Laptop 
    # GATEWAY_IP = "192.168.0.125"
    # GATEWAY_MAC = "24:b2:b9:3e:22:13"
    
    # Attack timing
    ARP_POISON_INTERVAL = 2  # seconds between ARP poison packets
    
    # HTTP Injection Configuration
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

# ==========================================
# DEFENSE CONFIGURATION
# ==========================================

class DefenseConfig:
    """Configuration for defense and monitoring tools"""
    
    # Alert thresholds
    ALERT_THRESHOLD = 3              # Number of suspicious events before alert
    TIME_WINDOW = 60                 # Time window for alert counting (seconds)
    MAC_CHANGE_THRESHOLD = 60        # Seconds - rapid MAC changes are suspicious
    
    # Monitoring settings
    ARP_MONITOR_INTERVAL = 5         # Seconds between ARP table checks
    GATEWAY_VALIDATION_INTERVAL = 30 # Seconds between gateway checks
    
    # Defense features
    ENABLE_COUNTERMEASURES = True    # Send counter-ARP packets
    ENABLE_STATIC_ARP = True         # Set static ARP entries
    ENABLE_EMAIL_ALERTS = False      # Email notifications
    ENABLE_DESKTOP_NOTIFICATIONS = True
    
    # Validation settings
    VALIDATION_THRESHOLD = 3         # Minimum validations before trusting
    CACHE_TIMEOUT = 300              # ARP cache timeout (seconds)
    MULTIPLE_VALIDATION = True       # Send multiple ARP requests for validation
    DNS_VALIDATION = True            # Cross-check with DNS
    
    # Trusted DNS servers
    TRUSTED_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    
    # Notification settings
    NOTIFICATION_EMAIL = None        # Set to email address for alerts
    LOG_LEVEL = "INFO"              # DEBUG, INFO, WARNING, ERROR, CRITICAL

# ==========================================
# NETWORK DISCOVERY CONFIGURATION
# ==========================================

class ScannerConfig:
    """Configuration for network device scanner"""
    
    # Scanning options
    DETAILED_SCAN = False           # Enable nmap scanning (slower)
    PING_SWEEP_THREADS = 50         # Number of parallel ping threads
    
    # MAC vendor database
    MAC_VENDOR_URLS = [
        "https://maclookup.app/downloads/json-database/get-db",
        "https://raw.githubusercontent.com/deepakthoughtwin/MAC-Address-Dataset/master/mac_vendor.json",
        "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
    ]
    
    # Cache settings
    MAC_VENDOR_CACHE_FILE = "mac_vendors.json"
    SCAN_RESULTS_FILE = "network_scan_results.json"
    
    # Display options
    DEFAULT_SORT = "ip"             # ip, type, vendor
    SHOW_ENHANCED_VENDOR_INFO = True

# ==========================================
# FILE AND PATH CONFIGURATION
# ==========================================

class PathConfig:
    """File paths and logging configuration"""
    
    # Base directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Log files
    ARP_DEFENSE_LOG = "arp_defense.log"
    NETWORK_MONITOR_LOG = "network_monitor.log"
    ATTACK_LOG = "attack.log"
    
    # Configuration files
    ARP_DEFENSE_CONFIG = "arp_defense_config.json"
    SECURE_ARP_CONFIG = "secure_arp_config.json"
    NETWORK_BASELINE = "network_baseline.json"
    
    # Database files
    MAC_VENDOR_DB = "mac_vendors.json"
    TRUSTED_DEVICES_DB = "trusted_devices.json"

# ==========================================
# SECURITY CONFIGURATION
# ==========================================

class SecurityConfig:
    """Security and safety settings"""
    
    # Safety checks
    REQUIRE_CONFIRMATION = True     # Require user confirmation before attacks
    MAX_ATTACK_DURATION = 3600      # Maximum attack duration (1 hour)
    AUTO_CLEANUP = True             # Automatically cleanup on exit
    
    # Legal and ethical settings
    SHOW_LEGAL_WARNING = True       # Show legal disclaimer
    LOG_ACTIVITIES = True           # Log all activities for audit
    
    # Restricted networks (will refuse to attack these)
    RESTRICTED_NETWORKS = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "169.254.0.0/16"  # Link-local
    ]

# ==========================================
# UTILITY FUNCTIONS
# ==========================================

def get_current_config_summary():
    """Get a summary of current configuration"""
    return {
        'timestamp': datetime.now().isoformat(),
        'network': {
            'interface': NetworkConfig.INTERFACE,
            'network_range': NetworkConfig.NETWORK_RANGE
        },
        'attack_target': {
            'victim_ip': AttackConfig.VICTIM_IP,
            'gateway_ip': AttackConfig.GATEWAY_IP
        },
        'defense': {
            'countermeasures_enabled': DefenseConfig.ENABLE_COUNTERMEASURES,
            'static_arp_enabled': DefenseConfig.ENABLE_STATIC_ARP
        },
        'security': {
            'require_confirmation': SecurityConfig.REQUIRE_CONFIRMATION,
            'auto_cleanup': SecurityConfig.AUTO_CLEANUP
        }
    }

def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check required network settings
    if not NetworkConfig.INTERFACE:
        errors.append("Network interface not specified")
    
    # Check attack targets
    if AttackConfig.VICTIM_IP == AttackConfig.GATEWAY_IP:
        errors.append("Victim and gateway IP cannot be the same")
    
    # Check MAC addresses format
    import re
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    
    if not mac_pattern.match(AttackConfig.VICTIM_MAC):
        errors.append("Invalid victim MAC address format")
    
    if not mac_pattern.match(AttackConfig.GATEWAY_MAC):
        errors.append("Invalid gateway MAC address format")
    
    return errors

def load_config_from_file(config_file="user_config.py"):
    """Load user-specific configuration overrides"""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("user_config", config_file)
        if spec and spec.loader:
            user_config = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(user_config)
            
            # Apply user overrides
            if hasattr(user_config, 'NETWORK_INTERFACE'):
                NetworkConfig.INTERFACE = user_config.NETWORK_INTERFACE
            
            if hasattr(user_config, 'VICTIM_IP'):
                AttackConfig.VICTIM_IP = user_config.VICTIM_IP
            
            if hasattr(user_config, 'VICTIM_MAC'):
                AttackConfig.VICTIM_MAC = user_config.VICTIM_MAC
            
            if hasattr(user_config, 'GATEWAY_IP'):
                AttackConfig.GATEWAY_IP = user_config.GATEWAY_IP
            
            if hasattr(user_config, 'GATEWAY_MAC'):
                AttackConfig.GATEWAY_MAC = user_config.GATEWAY_MAC
            
            print(f"✅ Loaded user configuration from {config_file}")
            return True
            
    except FileNotFoundError:
        print(f"ℹ️  No user config file found at {config_file}")
    except Exception as e:
        print(f"⚠️  Error loading user config: {e}")
    
    return False

def create_user_config_template():
    """Create a template user configuration file"""
    template = '''#!/usr/bin/env python3
"""
User Configuration Template
Copy this file and modify the values for your network
"""

# Network Configuration
NETWORK_INTERFACE = "wlp2s0"  # Your network interface
NETWORK_RANGE = "192.168.0.0/24"  # Your network range

# Attack Target Configuration
VICTIM_IP = "192.168.0.105"
VICTIM_MAC = "9a:be:d0:91:f3:76"

GATEWAY_IP = "192.168.0.1"
GATEWAY_MAC = "40:ed:00:4a:67:44"

# Custom injection payload
CUSTOM_INJECTION = b"<h1>Custom Attack Payload</h1>"

# Safety settings
REQUIRE_CONFIRMATION = True
MAX_ATTACK_DURATION = 1800  # 30 minutes

# Defense settings
ENABLE_EMAIL_ALERTS = False
NOTIFICATION_EMAIL = None  # "admin@example.com"
'''
    
    try:
        with open('user_config_template.py', 'w') as f:
            f.write(template)
        print("✅ Created user_config_template.py")
        print("📝 Copy and modify this file to customize your configuration")
    except Exception as e:
        print(f"❌ Failed to create template: {e}")

# ==========================================
# INITIALIZATION
# ==========================================

def initialize_config():
    """Initialize configuration system"""
    print("🔧 Initializing configuration system...")
    
    # Validate current config
    errors = validate_config()
    if errors:
        print("⚠️  Configuration validation warnings:")
        for error in errors:
            print(f"   • {error}")
    
    # Try to load user config
    load_config_from_file()
    
    # Create template if it doesn't exist
    if not os.path.exists('user_config_template.py'):
        create_user_config_template()
    
    print("✅ Configuration system initialized")

# Auto-initialize when imported
if __name__ != "__main__":
    initialize_config()

# ==========================================
# MAIN FUNCTION FOR TESTING
# ==========================================

if __name__ == "__main__":
    print("🔧 ARP Cache Poisoning & MITM Tools - Configuration")
    print("=" * 60)
    
    # Initialize and validate
    initialize_config()
    
    # Show current configuration
    import json
    config_summary = get_current_config_summary()
    print(f"\n📋 Current Configuration Summary:")
    print(json.dumps(config_summary, indent=2))
    
    # Validate configuration
    errors = validate_config()
    if errors:
        print(f"\n❌ Configuration Errors:")
        for error in errors:
            print(f"   • {error}")
    else:
        print(f"\n✅ Configuration is valid")
    
    print(f"\n📝 To customize configuration:")
    print(f"   1. Copy user_config_template.py to user_config.py")
    print(f"   2. Modify the values in user_config.py")
    print(f"   3. The tools will automatically load your settings") 