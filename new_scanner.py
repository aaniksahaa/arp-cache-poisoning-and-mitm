#!/usr/bin/env python3
"""
New Network Device Scanner - Continuous ARP scanning with comprehensive device info
Combines reliable continuous scanning with enhanced device detection and JSON output
"""

import subprocess
import json
import time
import requests
import socket
import threading
from datetime import datetime
from collections import defaultdict
import re
import os

# Add required imports for scanning
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
    print("✅ Scapy available for ARP scanning")
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy not available. Install with: pip install scapy")
    exit(1)

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    print("⚠️  Tabulate not available. Install with: pip install tabulate")

try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False
    print("⚠️  Keyboard not available. Install with: pip install keyboard")

# Import centralized configuration
try:
    from config import NetworkConfig, ScannerConfig, DeviceFilterConfig
    DEFAULT_INTERFACE = NetworkConfig.INTERFACE
    DEFAULT_NETWORK_RANGE = NetworkConfig.NETWORK_RANGE
    MAC_VENDOR_CACHE_FILE = ScannerConfig.MAC_VENDOR_CACHE_FILE
    SCAN_RESULTS_FILE = ScannerConfig.SCAN_RESULTS_FILE
except ImportError:
    # Fallback configuration if config.py not available
    DEFAULT_INTERFACE = "eth0"
    DEFAULT_NETWORK_RANGE = "192.168.0.1/24"
    MAC_VENDOR_CACHE_FILE = "mac_vendors.json"
    SCAN_RESULTS_FILE = "scan_results.json"
    class DeviceFilterConfig:
        ENABLE_DEVICE_FILTERING = False
        KNOWN_DEVICES = {}
        @staticmethod
        def should_show_device(ip, mac, hostname, vendor, device_type):
            return True, "no_filtering"

# Device type detection patterns
DEVICE_PATTERNS = {
    'router': ['router', 'gateway', 'rt-', 'wifi', 'linksys', 'netgear', 'dlink', 'asus-router'],
    'access_point': ['ap-', 'access', 'wireless', 'wifi', 'repeater', 'extender'],
    'switch': ['switch', 'sw-', 'managed', 'unmanaged'],
    'printer': ['printer', 'print', 'hp-', 'canon', 'epson', 'brother', 'lexmark'],
    'phone': ['iphone', 'android', 'samsung', 'pixel', 'oneplus', 'huawei', 'xiaomi'],
    'tablet': ['ipad', 'tablet', 'kindle', 'surface'],
    'laptop': ['laptop', 'macbook', 'thinkpad', 'dell', 'hp', 'lenovo'],
    'desktop': ['desktop', 'pc-', 'workstation', 'imac'],
    'tv': ['tv', 'smart-tv', 'samsung-tv', 'lg-tv', 'roku', 'chromecast', 'apple-tv'],
    'iot': ['nest', 'alexa', 'echo', 'smart', 'sensor', 'camera', 'doorbell'],
    'gaming': ['xbox', 'playstation', 'nintendo', 'steam', 'console'],
    'nas': ['nas', 'synology', 'qnap', 'drobo', 'storage']
}

# Device icons (Unicode symbols)
DEVICE_ICONS = {
    'router': '🌐',
    'access_point': '📡',
    'switch': '🔀',
    'printer': '🖨️',
    'phone': '📱',
    'tablet': '📟',
    'laptop': '💻',
    'desktop': '🖥️',
    'tv': '📺',
    'iot': '🏠',
    'gaming': '🎮',
    'nas': '💾',
    'camera': '📷',
    'unknown': '❓'
}

class ContinuousNetworkScanner:
    def __init__(self, interface=DEFAULT_INTERFACE, network=DEFAULT_NETWORK_RANGE):
        self.interface = interface
        self.network = network
        self.devices = {}
        self.mac_vendors = {}
        self.running = True
        
        # Configure Scapy to be less verbose
        conf.verb = 0
        
        print(f"🔍 Continuous Network Scanner initialized")
        print(f"   Interface: {self.interface}")
        print(f"   Network: {self.network}")
        
        # Load MAC vendor database
        self.load_mac_vendor_database()
        
        # Check for root privileges
        self.check_privileges()
    
    def check_privileges(self):
        """Check if running with sufficient privileges for raw socket access"""
        import os
        if os.geteuid() != 0:
            print(f"ℹ️  Running without root privileges")
            print(f"   💡 For best results, run with: sudo python3 {__file__}")
        else:
            print(f"✅ Running with root privileges - full ARP scanning available")
    
    def load_mac_vendor_database(self):
        """Load MAC vendor database from local cache or download"""
        print("📋 Loading MAC vendor database...")
        
        # Try to load from local file first
        if self.load_saved_database():
            return
        
        # Download from online source
        try:
            self.download_mac_vendor_database()
        except Exception as e:
            print(f"⚠️  Could not download MAC vendor database: {e}")
            # Use basic hardcoded database
            self.mac_vendors = self.get_basic_mac_vendors()
            print(f"📋 Using fallback database with {len(self.mac_vendors)} vendors")
    
    def load_saved_database(self):
        """Load previously saved MAC database"""
        try:
            with open(MAC_VENDOR_CACHE_FILE, 'r') as f:
                data = json.load(f)
            
            # Handle both old and new format
            if isinstance(data, dict) and 'vendors' in data:
                self.mac_vendors = data.get('vendors', {})
                self.mac_vendor_details = data.get('details', {})
                print(f"✅ Loaded enhanced MAC database: {len(self.mac_vendors)} vendors")
            else:
                self.mac_vendors = data
                print(f"✅ Loaded basic MAC database: {len(self.mac_vendors)} vendors")
            
            return True
            
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"⚠️  Error loading saved database: {e}")
            return False
    
    def download_mac_vendor_database(self):
        """Download MAC vendor database from online source"""
        print("🌐 Downloading MAC vendor database...")
        
        try:
            url = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                self.parse_wireshark_manuf(response.text)
                
                # Save to local file
                with open(MAC_VENDOR_CACHE_FILE, 'w') as f:
                    json.dump(self.mac_vendors, f, indent=2)
                print(f"✅ Downloaded and cached {len(self.mac_vendors)} MAC vendors")
            else:
                raise Exception(f"HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Failed to download: {e}")
            raise
    
    def parse_wireshark_manuf(self, data):
        """Parse Wireshark manufacturer database format"""
        for line in data.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    mac_prefix = parts[0].replace(':', '').replace('-', '').upper()
                    vendor = parts[1]
                    
                    # Handle different prefix lengths
                    if '/' in mac_prefix:
                        mac_prefix = mac_prefix.split('/')[0]
                    
                    self.mac_vendors[mac_prefix] = vendor
    
    def get_basic_mac_vendors(self):
        """Basic MAC vendor database as fallback"""
        return {
            "000001": "Xerox Corporation",
            "000007": "Apple Computer",
            "00000C": "Cisco Systems, Inc",
            "00004C": "NEC Corporation",
            "001B63": "Apple",
            "3C0754": "Apple",
            "A85C2C": "Apple", 
            "F0766F": "Apple",
            "2CF0EE": "Apple",
            "001124": "Samsung Electronics",
            "0025E5": "Samsung Electronics",
            "002454": "Samsung Electronics",
            "002566": "Samsung Electronics",
            "0026CC": "Samsung Electronics",
            "60A4B7": "Netgear",
            "24B2B9": "HUAWEI TECHNOLOGIES CO.,LTD",
            "3C5282": "Huawei Technologies",
            "AC3743": "Huawei Technologies"
        }
    
    def get_vendor_from_mac(self, mac):
        """Get vendor name from MAC address"""
        mac_clean = mac.replace(':', '').replace('-', '').upper()
        
        # Try different prefix lengths (6, 7, 8, 9 characters)
        for length in [9, 8, 7, 6]:
            prefix = mac_clean[:length]
            if prefix in self.mac_vendors:
                return self.mac_vendors[prefix]
        
        # Try online lookup as fallback
        try:
            return self.lookup_mac_online(mac)
        except:
            return "Unknown Vendor"
    
    def lookup_mac_online(self, mac):
        """Lookup MAC address online"""
        try:
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                vendor = response.text.strip()
                # Cache the result
                mac_clean = mac.replace(':', '').replace('-', '').upper()
                self.mac_vendors[mac_clean[:6]] = vendor
                return vendor
        except:
            pass
        return "Unknown Vendor"
    
    def resolve_hostname(self, ip):
        """Resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def detect_device_type(self, hostname, vendor, mac):
        """Detect device type based on various indicators"""
        hostname_lower = hostname.lower() if hostname else ""
        vendor_lower = vendor.lower() if vendor else ""
        
        # Priority 1: Explicit device type indicators in hostname
        laptop_indicators = ['laptop', 'macbook', 'thinkpad', 'probook', 'pavilion', 'inspiron']
        if any(indicator in hostname_lower for indicator in laptop_indicators):
            return 'laptop'
        
        desktop_indicators = ['desktop', 'pc-', 'workstation', 'imac', 'mac-pro']
        if any(indicator in hostname_lower for indicator in desktop_indicators):
            return 'desktop'
        
        phone_indicators = ['iphone', 'android', 'galaxy', 'pixel', 'phone']
        if any(indicator in hostname_lower for indicator in phone_indicators):
            return 'phone'
        
        tablet_indicators = ['ipad', 'tablet', 'kindle', 'surface']
        if any(indicator in hostname_lower for indicator in tablet_indicators):
            return 'tablet'
        
        # Priority 2: Vendor-specific logic
        if 'apple' in vendor_lower:
            if 'ipad' in hostname_lower:
                return 'tablet'
            elif 'iphone' in hostname_lower:
                return 'phone'
            elif 'macbook' in hostname_lower:
                return 'laptop'
            elif 'imac' in hostname_lower:
                return 'desktop'
            else:
                return 'phone'  # Most common Apple devices
        
        # Network equipment vendors
        if any(x in vendor_lower for x in ['netgear', 'linksys', 'asus', 'tp-link', 'cisco']):
            return 'router'
        
        # Printer vendors
        if any(x in vendor_lower for x in ['canon', 'epson', 'brother', 'xerox', 'hp']):
            if any(x in hostname_lower for x in ['printer', 'print']):
                return 'printer'
            elif any(x in hostname_lower for x in ['laptop', 'desktop', 'probook']):
                return 'laptop'  # HP computers
        
        # Samsung/LG devices
        if any(x in vendor_lower for x in ['samsung', 'lg']):
            if 'tv' in hostname_lower:
                return 'tv'
            else:
                return 'phone'
        
        # Generic pattern matching
        for device_type, patterns in DEVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in hostname_lower or pattern in vendor_lower:
                    return device_type
        
        return 'unknown'
    
    def continuous_arp_scan(self):
        """Continuous ARP scanning using Scapy"""
        print(f"🔎 Starting continuous ARP scan on {self.network}...")
        
        # Create ARP request packet
        arp_request = ARP(pdst=self.network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        scan_count = 0
        
        while self.running:
            try:
                scan_count += 1
                
                # Send ARP requests and receive responses
                result = srp(packet, timeout=3, verbose=0)[0]
                
                new_devices = 0
                for _, received in result:
                    ip = received.psrc
                    mac = received.hwsrc
                    
                    # Skip invalid MACs
                    if mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]:
                        continue
                    
                    # Skip if already discovered
                    if ip in self.devices:
                        # Update last seen time
                        self.devices[ip]['last_seen'] = datetime.now().isoformat()
                        continue
                    
                    # New device discovered
                    new_devices += 1
                    
                    # Get vendor information
                    vendor = self.get_vendor_from_mac(mac)
                    
                    # Try to resolve hostname
                    hostname = self.resolve_hostname(ip)
                    
                    # Detect device type
                    device_type = self.detect_device_type(hostname, vendor, mac)
                    
                    # Create device entry
                    device_info = {
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'hostname': hostname,
                        'device_type': device_type,
                        'icon': DEVICE_ICONS.get(device_type, DEVICE_ICONS['unknown']),
                        'interface': self.interface,
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'source': 'continuous_arp',
                        'scan_round': scan_count
                    }
                    
                    # Apply device filtering if enabled
                    if hasattr(DeviceFilterConfig, 'ENABLE_DEVICE_FILTERING') and DeviceFilterConfig.ENABLE_DEVICE_FILTERING:
                        should_show, reason = DeviceFilterConfig.should_show_device(
                            ip, mac, hostname, vendor, device_type
                        )
                        
                        if should_show:
                            device_info['filter_reason'] = reason
                            if 'known_device:' in reason:
                                known_name = reason.split(':')[1]
                                device_info['known_as'] = known_name
                                device_info['device_priority'] = 'known'
                            elif reason == 'gateway_device':
                                device_info['device_priority'] = 'gateway'
                            else:
                                device_info['device_priority'] = 'normal'
                            
                            self.devices[ip] = device_info
                    else:
                        # No filtering, add all devices
                        device_info['device_priority'] = 'normal'
                        self.devices[ip] = device_info
                
                # Small delay between scans
                time.sleep(0.1)
                
            except Exception as e:
                print(f"⚠️  Scan error: {e}")
                time.sleep(1)
    
    def display_live_results(self):
        """Display results in real-time table format"""
        while self.running:
            try:
                # Clear screen
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print(f"🔄 CONTINUOUS NETWORK SCAN")
                print(f"{'='*80}")
                print(f"📊 Devices discovered: {len(self.devices)}")
                print(f"⏰ Last update: {datetime.now().strftime('%H:%M:%S')}")
                print(f"🌐 Network: {self.network}")
                print(f"{'='*80}")
                
                if self.devices:
                    # Prepare table data
                    entries = list(self.devices.items())
                    
                    # Sort by priority and IP
                    def sort_key(item):
                        ip, device = item
                        priority = device.get('device_priority', 'normal')
                        if priority == 'known':
                            return (0, tuple(map(int, ip.split('.'))))
                        elif priority == 'gateway':
                            return (1, tuple(map(int, ip.split('.'))))
                        else:
                            return (2, tuple(map(int, ip.split('.'))))
                    
                    entries.sort(key=sort_key)
                    
                    if TABULATE_AVAILABLE:
                        # Use tabulate for nice formatting
                        table_data = []
                        for i, (ip, device) in enumerate(entries, 1):
                            icon = device.get('icon', '❓')
                            vendor = device.get('vendor', 'Unknown')[:25]
                            hostname = device.get('hostname', 'Unknown')[:20] if device.get('hostname') else 'Unknown'
                            device_type = device.get('device_type', 'unknown').title()
                            
                            # Add priority indicator
                            priority = device.get('device_priority', 'normal')
                            if priority == 'known':
                                known_name = device.get('known_as', 'Known')
                                device_type = f"⭐{device_type} ({known_name})"
                            elif priority == 'gateway':
                                device_type = f"🌐{device_type}"
                            
                            table_data.append([i, f"{icon} {ip}", hostname, vendor, device_type])
                        
                        print(tabulate(table_data, 
                                     headers=["#", "IP Address", "Hostname", "Vendor", "Type"],
                                     tablefmt="grid"))
                    else:
                        # Simple text format fallback
                        for i, (ip, device) in enumerate(entries, 1):
                            icon = device.get('icon', '❓')
                            vendor = device.get('vendor', 'Unknown')[:30]
                            hostname = device.get('hostname', 'Unknown')[:20] if device.get('hostname') else 'Unknown'
                            
                            priority = device.get('device_priority', 'normal')
                            prefix = ""
                            if priority == 'known':
                                prefix = "⭐ "
                            elif priority == 'gateway':
                                prefix = "🌐 "
                            
                            print(f"{i:2d}. {prefix}{icon} {ip:15s} | {vendor:30s} | {hostname:20s}")
                
                print(f"\n{'='*80}")
                if KEYBOARD_AVAILABLE:
                    print("Press 'q' to stop scanning and save results")
                else:
                    print("Press Ctrl+C to stop scanning and save results")
                print(f"{'='*80}")
                
                time.sleep(1)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                # Continue on display errors
                time.sleep(1)
    
    def save_results(self, filename=None):
        """Save scan results to JSON file"""
        if not filename:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        if not self.devices:
            print("❌ No devices to save")
            return False
        
        # Prepare results data
        results = {
            'timestamp': datetime.now().isoformat(),
            'interface': self.interface,
            'network': self.network,
            'total_devices': len(self.devices),
            'scan_type': 'continuous_arp',
            'devices': self.devices,
            'scan_metadata': {
                'mac_vendor_database_size': len(self.mac_vendors),
                'filtering_enabled': hasattr(DeviceFilterConfig, 'ENABLE_DEVICE_FILTERING') and DeviceFilterConfig.ENABLE_DEVICE_FILTERING
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"💾 Results saved to {filename}")
            print(f"   📊 {len(self.devices)} devices saved")
            
            # Also save to standard filename for compatibility
            if filename != SCAN_RESULTS_FILE:
                with open(SCAN_RESULTS_FILE, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"   📋 Also saved to {SCAN_RESULTS_FILE} for compatibility")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to save results: {e}")
            return False
    
    def display_final_results(self):
        """Display final results after scanning stops"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(f"🎯 FINAL SCAN RESULTS")
        print(f"{'='*80}")
        print(f"📊 Total devices discovered: {len(self.devices)}")
        print(f"🌐 Network: {self.network}")
        print(f"⏰ Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")
        
        if not self.devices:
            print("❌ No devices found")
            return
        
        # Sort devices by priority and IP
        entries = list(self.devices.items())
        def sort_key(item):
            ip, device = item
            priority = device.get('device_priority', 'normal')
            if priority == 'known':
                return (0, tuple(map(int, ip.split('.'))))
            elif priority == 'gateway':
                return (1, tuple(map(int, ip.split('.'))))
            else:
                return (2, tuple(map(int, ip.split('.'))))
        
        entries.sort(key=sort_key)
        
        # Display detailed results
        for i, (ip, device) in enumerate(entries, 1):
            icon = device.get('icon', '❓')
            device_type = device.get('device_type', 'unknown').title()
            vendor = device.get('vendor', 'Unknown')
            hostname = device.get('hostname', 'Unknown')
            mac = device.get('mac', 'Unknown')
            priority = device.get('device_priority', 'normal')
            
            # Priority indicator
            if priority == 'known':
                priority_indicator = "🎯 KNOWN DEVICE"
                known_name = device.get('known_as', 'Unknown')
                device_type = f"{device_type} ({known_name})"
            elif priority == 'gateway':
                priority_indicator = "🌐 GATEWAY"
            else:
                priority_indicator = "📍 DEVICE"
            
            print(f"\n{i:2d}. {priority_indicator} {icon} {device_type}")
            print(f"     📍 IP: {ip}")
            print(f"     🏷️  Hostname: {hostname}")
            print(f"     🔧 Vendor: {vendor}")
            print(f"     📝 MAC: {mac}")
            print(f"     ⏰ First seen: {device.get('first_seen', 'Unknown')}")
        
        # Show summary statistics
        print(f"\n{'='*80}")
        print(f"📊 DEVICE SUMMARY:")
        
        # Device type counts
        device_types = defaultdict(int)
        vendors = defaultdict(int)
        priorities = defaultdict(int)
        
        for device in self.devices.values():
            device_types[device.get('device_type', 'unknown')] += 1
            vendors[device.get('vendor', 'Unknown')] += 1
            priorities[device.get('device_priority', 'normal')] += 1
        
        print(f"\n🔍 Device Types:")
        for dtype, count in sorted(device_types.items()):
            icon = DEVICE_ICONS.get(dtype, '❓')
            print(f"   {icon} {dtype.title()}: {count}")
        
        if hasattr(DeviceFilterConfig, 'ENABLE_DEVICE_FILTERING') and DeviceFilterConfig.ENABLE_DEVICE_FILTERING:
            print(f"\n🎯 Device Priorities:")
            priority_icons = {'known': '🎯', 'gateway': '🌐', 'normal': '📍'}
            for priority, count in sorted(priorities.items()):
                icon = priority_icons.get(priority, '📍')
                print(f"   {icon} {priority.title()}: {count}")
        
        print(f"\n🏭 Top Vendors:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   • {vendor}: {count}")
        
        print(f"{'='*80}")
    
    def run(self):
        """Main scanning loop"""
        print(f"🚀 Starting continuous network scanning...")
        print(f"   Network: {self.network}")
        print(f"   Interface: {self.interface}")
        
        if hasattr(DeviceFilterConfig, 'ENABLE_DEVICE_FILTERING') and DeviceFilterConfig.ENABLE_DEVICE_FILTERING:
            print(f"   🔽 Device filtering: ENABLED")
            if hasattr(DeviceFilterConfig, 'KNOWN_DEVICES'):
                print(f"   🎯 Looking for {len(DeviceFilterConfig.KNOWN_DEVICES)} known devices")
        else:
            print(f"   🔽 Device filtering: DISABLED")
        
        print(f"\n{'='*80}")
        
        try:
            # Start background scanning
            scan_thread = threading.Thread(target=self.continuous_arp_scan, daemon=True)
            scan_thread.start()
            
            # Start display thread
            display_thread = threading.Thread(target=self.display_live_results, daemon=True)
            display_thread.start()
            
            # Wait for user input to stop
            if KEYBOARD_AVAILABLE:
                # Wait for 'q' key
                while self.running:
                    if keyboard.is_pressed('q'):
                        print("\n🛑 Stopping scan...")
                        self.running = False
                        break
                    time.sleep(0.1)
            else:
                # Wait for Ctrl+C
                try:
                    while self.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping scan...")
                    self.running = False
            
            # Give threads time to finish
            time.sleep(1)
            
            # Display final results
            self.display_final_results()
            
            # Save results
            if self.devices:
                save_file = input(f"\nSave results? (Y/n): ").lower().strip()
                if save_file != 'n':
                    custom_filename = input("Enter filename (or press Enter for auto): ").strip()
                    if custom_filename:
                        self.save_results(custom_filename)
                    else:
                        self.save_results()
                    print("✅ Results saved successfully!")
                else:
                    print("Results not saved")
            else:
                print("No devices found to save")
            
        except KeyboardInterrupt:
            print("\n🛑 Scan interrupted")
            self.running = False
        except Exception as e:
            print(f"❌ Scan error: {e}")
            self.running = False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Continuous Network Device Scanner")
    parser.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                       help="Network interface to use")
    parser.add_argument("-n", "--network", default=DEFAULT_NETWORK_RANGE,
                       help="Network range to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("--no-filter", action="store_true",
                       help="Disable device filtering")
    parser.add_argument("--install-deps", action="store_true",
                       help="Install required dependencies")
    
    args = parser.parse_args()
    
    if args.install_deps:
        print("📦 Installing required dependencies...")
        try:
            import subprocess
            import sys
            subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy", "tabulate", "keyboard", "requests"])
            print("✅ Dependencies installed successfully!")
        except Exception as e:
            print(f"❌ Failed to install dependencies: {e}")
        return
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy is required for ARP scanning")
        print("Install with: pip install scapy")
        print("Or run: python3 new_scanner.py --install-deps")
        return
    
    # Override filtering if requested
    if args.no_filter and hasattr(DeviceFilterConfig, 'ENABLE_DEVICE_FILTERING'):
        DeviceFilterConfig.ENABLE_DEVICE_FILTERING = False
        print("🔽 Device filtering disabled")
    
    # Create and run scanner
    scanner = ContinuousNetworkScanner(args.interface, args.network)
    scanner.run()

if __name__ == "__main__":
    main() 