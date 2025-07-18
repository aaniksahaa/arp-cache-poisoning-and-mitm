#!/usr/bin/env python3
"""
Network Device Scanner - Comprehensive device discovery and identification
Identifies device types, manufacturers, and detailed information from MAC addresses
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

# Import centralized configuration
from config import NetworkConfig, ScannerConfig, PathConfig

# Use configuration values
DEFAULT_INTERFACE = NetworkConfig.INTERFACE
DEFAULT_NETWORK_RANGE = NetworkConfig.NETWORK_RANGE
DETAILED_SCAN = ScannerConfig.DETAILED_SCAN
PING_SWEEP_THREADS = ScannerConfig.PING_SWEEP_THREADS
MAC_VENDOR_CACHE_FILE = ScannerConfig.MAC_VENDOR_CACHE_FILE
SCAN_RESULTS_FILE = ScannerConfig.SCAN_RESULTS_FILE
DEFAULT_SORT = ScannerConfig.DEFAULT_SORT
SHOW_ENHANCED_VENDOR_INFO = ScannerConfig.SHOW_ENHANCED_VENDOR_INFO

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

class NetworkDeviceScanner:
    def __init__(self, interface=DEFAULT_INTERFACE):
        self.interface = interface
        self.devices = {}
        self.mac_vendors = {}
        self.load_mac_vendor_database()
        
        print(f"🔍 Network Device Scanner initialized")
        print(f"   Interface: {self.interface}")
    
    def load_mac_vendor_database(self):
        """Load MAC vendor database from online or local sources"""
        print("📋 Loading MAC vendor database...")
        
        # Try to load from enhanced local file first
        if self.load_saved_database():
            return
        
        # Download from online API
        try:
            self.download_mac_vendor_database()
        except Exception as e:
            print(f"⚠️  Could not download MAC vendor database: {e}")
            # Use a basic hardcoded database
            self.mac_vendors = self.get_basic_mac_vendors()
            print(f"📋 Using fallback database with {len(self.mac_vendors)} vendors")
    
    def download_mac_vendor_database(self):
        """Download MAC vendor database from online source"""
        print("🌐 Downloading MAC vendor database...")
        
        # Try JSON format first (preferred)
        json_urls = [
            "https://maclookup.app/downloads/json-database/get-db",
            "https://raw.githubusercontent.com/deepakthoughtwin/MAC-Address-Dataset/master/mac_vendor.json"
        ]
        
        for url in json_urls:
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    # Try to parse as JSON
                    try:
                        mac_data = response.json()
                        self.parse_json_mac_database(mac_data)
                        
                        # Save to local file
                        with open(MAC_VENDOR_CACHE_FILE, 'w') as f:
                            json.dump(self.mac_vendors, f, indent=2)
                        print(f"✅ Downloaded and cached {len(self.mac_vendors)} MAC vendors (JSON format)")
                        return
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                print(f"⚠️  Failed to download from {url}: {e}")
                continue
        
        # Fallback to Wireshark format
        try:
            url = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                self.parse_wireshark_manuf(response.text)
                
                # Save to local file
                with open(MAC_VENDOR_CACHE_FILE, 'w') as f:
                    json.dump(self.mac_vendors, f, indent=2)
                print(f"✅ Downloaded and cached {len(self.mac_vendors)} MAC vendors (Wireshark format)")
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
    
    def parse_json_mac_database(self, mac_data):
        """Parse JSON MAC vendor database"""
        print("📋 Parsing JSON MAC vendor database...")
        
        # Handle different JSON structures
        if isinstance(mac_data, list):
            # List of objects format (like your example)
            for entry in mac_data:
                if isinstance(entry, dict):
                    mac_prefix = entry.get('macPrefix', '').replace(':', '').replace('-', '').upper()
                    vendor_name = entry.get('vendorName', '')
                    
                    if mac_prefix and vendor_name:
                        # Store additional metadata if available
                        vendor_info = {
                            'name': vendor_name,
                            'block_type': entry.get('blockType', 'Unknown'),
                            'private': entry.get('private', False),
                            'last_update': entry.get('lastUpdate', 'Unknown')
                        }
                        
                        # For compatibility, store just the name in main lookup
                        self.mac_vendors[mac_prefix] = vendor_name
                        
                        # Store full info in separate dict for advanced features
                        if not hasattr(self, 'mac_vendor_details'):
                            self.mac_vendor_details = {}
                        self.mac_vendor_details[mac_prefix] = vendor_info
        
        elif isinstance(mac_data, dict):
            # Dictionary format
            for mac_prefix, vendor_info in mac_data.items():
                mac_clean = mac_prefix.replace(':', '').replace('-', '').upper()
                
                if isinstance(vendor_info, str):
                    self.mac_vendors[mac_clean] = vendor_info
                elif isinstance(vendor_info, dict):
                    vendor_name = vendor_info.get('name', vendor_info.get('vendorName', 'Unknown'))
                    self.mac_vendors[mac_clean] = vendor_name
                    
                    # Store detailed info
                    if not hasattr(self, 'mac_vendor_details'):
                        self.mac_vendor_details = {}
                    self.mac_vendor_details[mac_clean] = vendor_info
    
    def save_mac_database(self):
        """Save the current MAC vendor database to file"""
        database_data = {
            'vendors': self.mac_vendors,
            'details': getattr(self, 'mac_vendor_details', {}),
            'timestamp': datetime.now().isoformat(),
            'total_entries': len(self.mac_vendors)
        }
        
        with open(MAC_VENDOR_CACHE_FILE, 'w') as f:
            json.dump(database_data, f, indent=2)
        
        print(f"💾 MAC vendor database saved to {MAC_VENDOR_CACHE_FILE}")
        print(f"   📊 {len(self.mac_vendors)} vendors with {len(getattr(self, 'mac_vendor_details', {}))} detailed entries")
    
    def load_saved_database(self):
        """Load previously saved MAC database with details"""
        try:
            with open(MAC_VENDOR_CACHE_FILE, 'r') as f:
                data = json.load(f)
            
            # Handle both old and new format
            if isinstance(data, dict) and 'vendors' in data:
                # New enhanced format
                self.mac_vendors = data.get('vendors', {})
                self.mac_vendor_details = data.get('details', {})
                print(f"✅ Loaded enhanced MAC database: {len(self.mac_vendors)} vendors")
                if self.mac_vendor_details:
                    print(f"   🔍 Enhanced details for {len(self.mac_vendor_details)} vendors")
            else:
                # Old simple format
                self.mac_vendors = data
                print(f"✅ Loaded basic MAC database: {len(self.mac_vendors)} vendors")
            
            return True
            
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"⚠️  Error loading saved database: {e}")
            return False
    
    def get_basic_mac_vendors(self):
        """Enhanced basic MAC vendor database as fallback"""
        return {
            "000001": "Xerox Corporation",
            "000002": "BBN Technologies",
            "000003": "MD Technologies",
            "000004": "Antronix",
            "000005": "Symbolics Inc",
            "000006": "Siemens Nixdorf",
            "000007": "Apple Computer",
            "000008": "BBN Technologies",
            "000009": "Hewlett-Packard",
            "00000A": "Nestar Systems",
            "00000B": "Unisys",
            "00000C": "Cisco Systems, Inc",
            "00000D": "FIBRONICS LTD.",
            "00000E": "FUJITSU LIMITED",
            "00001B": "Novell, Inc.",
            "000023": "ABB INDUSTRIAL SYSTEMS AB",
            "000031": "QPSX COMMUNICATIONS, LTD.",
            "000037": "OXFORD METRICS LIMITED",
            "00003C": "AUSPEX SYSTEMS INC.",
            "00003E": "SIMPACT",
            "00003F": "SYNTREX, INC.",
            "000046": "OLIVETTI NORTH AMERICA",
            "000049": "APRICOT COMPUTERS, LTD",
            "00004A": "ADC CODENOLL TECHNOLOGY CORP.",
            "00004C": "NEC Corporation",
            "000050": "RADISYS CORPORATION",
            "000051": "HOB ELECTRONIC GMBH & CO. KG",
            "000052": "Intrusion.com, Inc.",
            "000058": "RACORE COMPUTER PRODUCTS INC.",
            "00005A": "SysKonnect GmbH",
            "00005E": "IANA",
            "3C5282": "Huawei Technologies",
            "AC3743": "Huawei Technologies",
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
            "24B2B9": "HUAWEI TECHNOLOGIES CO.,LTD"
        }
    
    def get_vendor_from_mac(self, mac):
        """Get vendor name from MAC address with enhanced details"""
        mac_clean = mac.replace(':', '').replace('-', '').upper()
        
        # Try different prefix lengths (6, 7, 8, 9 characters)
        vendor_info = None
        for length in [9, 8, 7, 6]:
            prefix = mac_clean[:length]
            if prefix in self.mac_vendors:
                vendor_name = self.mac_vendors[prefix]
                
                # Get additional details if available
                if hasattr(self, 'mac_vendor_details') and prefix in self.mac_vendor_details:
                    vendor_info = self.mac_vendor_details[prefix].copy()
                    vendor_info['prefix_length'] = length
                    vendor_info['matched_prefix'] = prefix
                
                return vendor_name, vendor_info
        
        # Try online lookup as fallback
        try:
            vendor_name = self.lookup_mac_online(mac)
            return vendor_name, None
        except:
            return "Unknown Vendor", None
    
    def lookup_mac_online(self, mac):
        """Lookup MAC address online"""
        try:
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                vendor = response.text.strip()
                # Cache the result
                mac_clean = mac.replace(':', '').replace('-', '').upper()
                self.mac_vendors[mac_clean[:6]] = vendor
                return vendor
        except:
            pass
        return "Unknown Vendor"
    
    def detect_device_type(self, hostname, vendor, mac, additional_info):
        """Detect device type based on various indicators"""
        hostname_lower = hostname.lower() if hostname else ""
        vendor_lower = vendor.lower() if vendor else ""
        
        # Priority 1: Explicit device type indicators in hostname
        # Check for explicit laptop/computer indicators first
        laptop_indicators = ['laptop', 'macbook', 'thinkpad', 'probook', 'pavilion', 'inspiron', 'latitude', 'precision', 'elitebook']
        if any(indicator in hostname_lower for indicator in laptop_indicators):
            return 'laptop'
        
        desktop_indicators = ['desktop', 'pc-', 'workstation', 'imac', 'mac-pro', 'optiplex', 'compaq']
        if any(indicator in hostname_lower for indicator in desktop_indicators):
            return 'desktop'
        
        # Phone indicators
        phone_indicators = ['iphone', 'android', 'galaxy', 'pixel', 'oneplus', 'phone']
        if any(indicator in hostname_lower for indicator in phone_indicators):
            return 'phone'
        
        # Tablet indicators
        tablet_indicators = ['ipad', 'tablet', 'kindle', 'surface']
        if any(indicator in hostname_lower for indicator in tablet_indicators):
            return 'tablet'
        
        # TV indicators
        tv_indicators = ['tv', 'smart-tv', 'roku', 'chromecast', 'apple-tv']
        if any(indicator in hostname_lower for indicator in tv_indicators):
            return 'tv'
        
        # Router/Network indicators
        router_indicators = ['router', 'gateway', 'rt-', 'wifi', 'access-point', 'ap-']
        if any(indicator in hostname_lower for indicator in router_indicators):
            return 'router'
        
        # Printer indicators (more specific)
        printer_indicators = ['printer', 'print-server', 'laserjet', 'officejet', 'deskjet', 'pixma', 'workforce']
        if any(indicator in hostname_lower for indicator in printer_indicators):
            return 'printer'
        
        # Priority 2: Vendor-specific logic with hostname context
        if any(x in vendor_lower for x in ['apple']):
            if 'ipad' in hostname_lower:
                return 'tablet'
            elif 'iphone' in hostname_lower:
                return 'phone'
            elif 'macbook' in hostname_lower:
                return 'laptop'
            elif 'imac' in hostname_lower or 'mac-pro' in hostname_lower:
                return 'desktop'
            elif 'apple-tv' in hostname_lower:
                return 'tv'
            else:
                # Default Apple device detection based on common patterns
                if 'book' in hostname_lower:
                    return 'laptop'
                elif any(x in hostname_lower for x in ['mac', 'macintosh']):
                    return 'desktop'
                else:
                    return 'phone'  # Most common Apple devices are phones
        
        # HP-specific logic (distinguish between computers and printers)
        if any(x in vendor_lower for x in ['hp', 'hewlett', 'packard']):
            # If hostname contains computer/laptop indicators, it's a computer
            if any(x in hostname_lower for x in ['probook', 'elitebook', 'pavilion', 'envy', 'omen', 'spectre', 'laptop', 'notebook']):
                return 'laptop'
            elif any(x in hostname_lower for x in ['desktop', 'compaq', 'workstation']):
                return 'desktop'
            elif any(x in hostname_lower for x in ['laserjet', 'officejet', 'deskjet', 'envy-printer', 'printer']):
                return 'printer'
            else:
                # If vendor is HP but no specific indicators, check additional info
                if additional_info:
                    info_lower = str(additional_info).lower()
                    if any(x in info_lower for x in ['ssh', 'rdp', '3389', '22']):
                        return 'desktop'  # Has remote access ports
                    elif any(x in info_lower for x in ['631', 'ipp', 'printer']):
                        return 'printer'  # Has printer ports
                # Default for HP without clear indicators
                return 'unknown'
        
        # Samsung/LG/Sony logic
        if any(x in vendor_lower for x in ['samsung', 'lg', 'sony']):
            if 'tv' in hostname_lower or 'smart' in hostname_lower:
                return 'tv'
            elif any(x in hostname_lower for x in ['galaxy', 'phone', 'mobile']):
                return 'phone'
            elif 'tablet' in hostname_lower:
                return 'tablet'
            else:
                return 'phone'  # Most common for these vendors
        
        # Canon/Epson/Brother are typically printers
        if any(x in vendor_lower for x in ['canon', 'epson', 'brother', 'xerox', 'kyocera']):
            return 'printer'
        
        # Network equipment vendors
        if any(x in vendor_lower for x in ['netgear', 'linksys', 'asus', 'tp-link', 'cisco', 'ubiquiti', 'mikrotik']):
            if any(x in hostname_lower for x in ['ap-', 'access-point', 'repeater', 'extender']):
                return 'access_point'
            else:
                return 'router'
        
        # Gaming console vendors
        if any(x in vendor_lower for x in ['microsoft', 'sony']) and any(x in hostname_lower for x in ['xbox', 'playstation', 'console']):
            return 'gaming'
        
        # Priority 3: Check additional info from nmap scan
        if additional_info:
            info_lower = str(additional_info).lower()
            
            # Check for specific services
            if any(x in info_lower for x in ['631', 'ipp', 'printer']):
                return 'printer'
            elif any(x in info_lower for x in ['80', 'http', '443', 'https']) and any(x in info_lower for x in ['ssh', 'telnet']):
                return 'router'
            elif any(x in info_lower for x in ['22', 'ssh', '3389', 'rdp']):
                return 'desktop'
            elif any(x in info_lower for x in ['139', '445', 'smb', 'netbios']):
                return 'desktop'
        
        # Priority 4: Generic hostname patterns
        for device_type, patterns in DEVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return device_type
        
        # Priority 5: Generic vendor patterns (less reliable)
        for device_type, patterns in DEVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in vendor_lower:
                    return device_type
        
        return 'unknown'
    
    def get_arp_table(self):
        """Get current ARP table"""
        devices = {}
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '(' in line and ')' in line and 'ether' in line:
                    # Parse: hostname (ip) at mac [ether] on interface
                    parts = line.split()
                    if len(parts) >= 4:
                        hostname = parts[0] if parts[0] != '?' else None
                        ip = parts[1][1:-1]  # Remove parentheses
                        mac = parts[3]
                        interface = parts[-1] if len(parts) > 5 else self.interface
                        
                        devices[ip] = {
                            'hostname': hostname,
                            'mac': mac,
                            'interface': interface,
                            'source': 'arp'
                        }
        except Exception as e:
            print(f"❌ Failed to get ARP table: {e}")
        
        return devices
    
    def ping_sweep(self, network=DEFAULT_NETWORK_RANGE):
        """Perform ping sweep to discover active devices"""
        print(f"🔍 Performing ping sweep on {network}...")
        
        # Extract network base (simple implementation)
        if network.endswith('/24'):
            base = network[:-3]
            base_parts = base.split('.')
            network_base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
        else:
            network_base = "192.168.0"
        
        active_ips = []
        
        def ping_ip(ip):
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=3)
                if result.returncode == 0:
                    active_ips.append(ip)
            except:
                pass
        
        # Ping common IPs in parallel
        threads = []
        for i in range(1, 255):
            ip = f"{network_base}.{i}"
            thread = threading.Thread(target=ping_ip, args=(ip,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        print(f"✅ Found {len(active_ips)} active devices")
        return active_ips
    
    def nmap_scan(self, ip):
        """Perform nmap scan for additional device information"""
        try:
            # Quick service detection
            result = subprocess.run(['nmap', '-sS', '-O', '--top-ports', '100', ip], 
                                  capture_output=True, text=True, timeout=30)
            
            info = {}
            if result.returncode == 0:
                output = result.stdout
                
                # Extract OS information
                if 'OS details:' in output:
                    os_line = [line for line in output.split('\n') if 'OS details:' in line]
                    if os_line:
                        info['os'] = os_line[0].split('OS details:')[1].strip()
                
                # Extract open ports
                open_ports = []
                for line in output.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        port_info = line.split()[0]
                        service = line.split()[-1] if len(line.split()) > 2 else 'unknown'
                        open_ports.append(f"{port_info} ({service})")
                
                if open_ports:
                    info['ports'] = open_ports
                
                # Extract device type hints
                if 'printer' in output.lower():
                    info['device_hint'] = 'printer'
                elif 'router' in output.lower():
                    info['device_hint'] = 'router'
                elif 'phone' in output.lower():
                    info['device_hint'] = 'phone'
            
            return info
        except Exception as e:
            return {}
    
    def resolve_hostname(self, ip):
        """Resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def get_dhcp_info(self):
        """Get DHCP lease information if available"""
        dhcp_info = {}
        try:
            # Try common DHCP lease file locations
            lease_files = [
                '/var/lib/dhcp/dhcpd.leases',
                '/var/lib/dhcpcd5/dhcpcd.leases',
                '/var/db/dhcpd.leases'
            ]
            
            for lease_file in lease_files:
                try:
                    with open(lease_file, 'r') as f:
                        content = f.read()
                        # Parse DHCP leases (simplified)
                        # This would need more sophisticated parsing
                        break
                except FileNotFoundError:
                    continue
        except:
            pass
        
        return dhcp_info
    
    def enhanced_device_scan(self, ip):
        """Perform enhanced scanning for device information"""
        info = {
            'hostname': None,
            'os': None,
            'ports': [],
            'device_hint': None,
            'vendor': 'Unknown',
            'last_seen': datetime.now().isoformat()
        }
        
        # Try hostname resolution
        info['hostname'] = self.resolve_hostname(ip)
        
        # Try nmap scan (if available)
        try:
            nmap_info = self.nmap_scan(ip)
            info.update(nmap_info)
        except:
            pass
        
        return info
    
    def scan_network(self, detailed=DETAILED_SCAN):
        """Comprehensive network scan"""
        print("🚀 Starting comprehensive network scan...")
        
        # Get devices from ARP table
        devices = self.get_arp_table()
        
        # Perform ping sweep to find additional devices
        active_ips = self.ping_sweep()
        
        # Add devices not in ARP table
        for ip in active_ips:
            if ip not in devices:
                devices[ip] = {
                    'hostname': None,
                    'mac': None,
                    'interface': self.interface,
                    'source': 'ping'
                }
        
        # Enhance device information
        for ip, device in devices.items():
            print(f"📡 Scanning {ip}...")
            
            # Get vendor information
            if device['mac']:
                device['vendor'], device['vendor_details'] = self.get_vendor_from_mac(device['mac'])
            else:
                device['vendor'] = 'Unknown'
            
            # Enhanced scanning
            if detailed:
                enhanced_info = self.enhanced_device_scan(ip)
                device.update(enhanced_info)
            else:
                # Quick hostname lookup
                device['hostname'] = device.get('hostname') or self.resolve_hostname(ip)
            
            # Detect device type
            device['device_type'] = self.detect_device_type(
                device.get('hostname'),
                device.get('vendor'),
                device.get('mac'),
                device.get('ports', [])
            )
            
            # Add icon
            device['icon'] = DEVICE_ICONS.get(device['device_type'], DEVICE_ICONS['unknown'])
            
            # Store in main devices dict
            self.devices[ip] = device
        
        print(f"✅ Scan complete! Found {len(self.devices)} devices")
        return self.devices
    
    def display_devices(self, sort_by=DEFAULT_SORT):
        """Display discovered devices in a nice format"""
        if not self.devices:
            print("❌ No devices found. Run scan_network() first.")
            return
        
        print(f"\n{'='*80}")
        print(f"🌐 NETWORK DEVICE DISCOVERY REPORT")
        print(f"{'='*80}")
        print(f"📅 Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔍 Total Devices: {len(self.devices)}")
        print(f"{'='*80}")
        
        # Sort devices
        if sort_by == 'type':
            sorted_devices = sorted(self.devices.items(), 
                                  key=lambda x: x[1].get('device_type', 'unknown'))
        elif sort_by == 'vendor':
            sorted_devices = sorted(self.devices.items(), 
                                  key=lambda x: x[1].get('vendor', 'Unknown'))
        else:  # sort by IP
            sorted_devices = sorted(self.devices.items(), 
                                  key=lambda x: tuple(map(int, x[0].split('.'))))
        
        for ip, device in sorted_devices:
            icon = device.get('icon', '❓')
            device_type = device.get('device_type', 'unknown').title()
            vendor = device.get('vendor', 'Unknown')
            hostname = device.get('hostname', 'Unknown')
            mac = device.get('mac', 'Unknown')
            
            print(f"\n{icon} {device_type}")
            print(f"   📍 IP Address: {ip}")
            print(f"   🏷️  Hostname: {hostname}")
            print(f"   🔧 Vendor: {vendor}")
            
            # Show enhanced vendor information if available
            vendor_details = device.get('vendor_details')
            if vendor_details and isinstance(vendor_details, dict):
                block_type = vendor_details.get('block_type', '')
                if block_type and block_type != 'Unknown':
                    print(f"   📋 Block Type: {block_type}")
                
                is_private = vendor_details.get('private')
                if is_private is not None:
                    privacy_status = "Private" if is_private else "Public"
                    print(f"   🔒 Registration: {privacy_status}")
                
                last_update = vendor_details.get('last_update', '')
                if last_update and last_update != 'Unknown':
                    print(f"   📅 Last Updated: {last_update}")
                
                matched_prefix = vendor_details.get('matched_prefix', '')
                prefix_length = vendor_details.get('prefix_length', 0)
                if matched_prefix:
                    print(f"   🔍 MAC Prefix: {matched_prefix} ({prefix_length} chars)")
            
            print(f"   📝 MAC Address: {mac}")
            
            if device.get('os'):
                print(f"   💾 OS: {device['os']}")
            
            if device.get('ports'):
                ports_str = ', '.join(device['ports'][:3])  # Show first 3 ports
                if len(device['ports']) > 3:
                    ports_str += f" (+{len(device['ports']) - 3} more)"
                print(f"   🔌 Open Ports: {ports_str}")
            
            print(f"   🔗 Interface: {device.get('interface', 'Unknown')}")
            print(f"   📡 Source: {device.get('source', 'Unknown')}")
        
        print(f"\n{'='*80}")
        
        # Device type summary
        device_types = defaultdict(int)
        vendors = defaultdict(int)
        block_types = defaultdict(int)
        
        for device in self.devices.values():
            device_types[device.get('device_type', 'unknown')] += 1
            vendors[device.get('vendor', 'Unknown')] += 1
            
            # Count block types if available
            vendor_details = device.get('vendor_details')
            if vendor_details and isinstance(vendor_details, dict):
                block_type = vendor_details.get('block_type', 'Unknown')
                block_types[block_type] += 1
        
        print(f"📊 DEVICE TYPE SUMMARY:")
        for dtype, count in sorted(device_types.items()):
            icon = DEVICE_ICONS.get(dtype, '❓')
            print(f"   {icon} {dtype.title()}: {count}")
        
        print(f"\n🏭 TOP VENDORS:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   • {vendor}: {count}")
        
        # Show block type summary if we have that data
        if block_types and any(bt != 'Unknown' for bt in block_types.keys()):
            print(f"\n📋 MAC BLOCK TYPES:")
            for block_type, count in sorted(block_types.items(), key=lambda x: x[1], reverse=True):
                if block_type != 'Unknown':
                    print(f"   • {block_type}: {count}")
        
        print(f"{'='*80}")
    
    def save_results(self, filename=SCAN_RESULTS_FILE):
        """Save scan results to JSON file with enhanced vendor data"""
        if not self.devices:
            print("❌ No devices to save. Run scan_network() first.")
            return
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'interface': self.interface,
            'total_devices': len(self.devices),
            'devices': self.devices,
            'scan_metadata': {
                'mac_vendor_database_size': len(self.mac_vendors),
                'enhanced_vendor_data': hasattr(self, 'mac_vendor_details'),
                'vendor_details_count': len(getattr(self, 'mac_vendor_details', {}))
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"💾 Results saved to {filename}")
        print(f"   📊 {len(self.devices)} devices with enhanced vendor data")
    
    def load_results(self, filename=SCAN_RESULTS_FILE):
        """Load previous scan results"""
        try:
            with open(filename, 'r') as f:
                results = json.load(f)
                self.devices = results.get('devices', {})
                print(f"📂 Loaded {len(self.devices)} devices from {filename}")
                return True
        except FileNotFoundError:
            print(f"❌ File {filename} not found")
            return False
    
    def monitor_network_changes(self, interval=60):
        """Monitor network for device changes"""
        print(f"👁️  Starting network monitoring (checking every {interval}s)...")
        print("Press Ctrl+C to stop")
        
        previous_devices = set()
        
        try:
            while True:
                current_scan = self.scan_network(detailed=False)
                current_devices = set(current_scan.keys())
                
                # Check for new devices
                new_devices = current_devices - previous_devices
                if new_devices:
                    print(f"\n🆕 NEW DEVICES DETECTED:")
                    for ip in new_devices:
                        device = current_scan[ip]
                        print(f"   {device.get('icon', '❓')} {ip} - {device.get('vendor', 'Unknown')}")
                
                # Check for disappeared devices
                disappeared = previous_devices - current_devices
                if disappeared:
                    print(f"\n📤 DEVICES OFFLINE:")
                    for ip in disappeared:
                        print(f"   ❌ {ip}")
                
                previous_devices = current_devices
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n👋 Network monitoring stopped")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Device Scanner")
    parser.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                       help="Network interface to use")
    parser.add_argument("--detailed", action="store_true",
                       help="Perform detailed scanning (slower)")
    parser.add_argument("--sort", choices=['ip', 'type', 'vendor'], default=DEFAULT_SORT,
                       help="Sort devices by")
    parser.add_argument("--save", help="Save results to file")
    parser.add_argument("--load", help="Load results from file")
    parser.add_argument("--monitor", type=int, metavar="SECONDS",
                       help="Monitor network changes (check interval)")
    
    args = parser.parse_args()
    
    scanner = NetworkDeviceScanner(args.interface)
    
    if args.load:
        if scanner.load_results(args.load):
            scanner.display_devices(args.sort)
        return
    
    if args.monitor:
        scanner.monitor_network_changes(args.monitor)
        return
    
    # Perform scan
    scanner.scan_network(detailed=args.detailed)
    scanner.display_devices(args.sort)
    
    if args.save:
        scanner.save_results(args.save)

if __name__ == "__main__":
    main() 