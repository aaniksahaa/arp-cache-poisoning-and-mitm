#!/usr/bin/env python3
"""
Secure ARP Client - Validates ARP responses to detect spoofing attacks
Implements multiple validation techniques for secure ARP resolution
"""

import socket
import json
import time
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

# Import centralized configuration
from config import NetworkConfig, DefenseConfig, PathConfig, SecurityConfig

# Use configuration values
INTERFACE = NetworkConfig.INTERFACE
VALIDATION_THRESHOLD = DefenseConfig.VALIDATION_THRESHOLD
CACHE_TIMEOUT = DefenseConfig.CACHE_TIMEOUT
DNS_VALIDATION = DefenseConfig.DNS_VALIDATION
MULTIPLE_VALIDATION = DefenseConfig.MULTIPLE_VALIDATION
TRUSTED_DNS_SERVERS = DefenseConfig.TRUSTED_DNS_SERVERS
CONFIG_FILE = PathConfig.SECURE_ARP_CONFIG

try:
    from scapy.all import ARP, Ether, srp, sr1
except ImportError:
    print("❌ Scapy not found. Install with: pip install scapy")
    exit(1)

class SecureARPClient:
    def __init__(self, interface=None, config_file=None):
        self.interface = interface or INTERFACE
        self.config_file = config_file or CONFIG_FILE
        
        # Configuration from centralized config
        self.validation_threshold = VALIDATION_THRESHOLD
        self.cache_timeout = CACHE_TIMEOUT
        self.dns_validation = DNS_VALIDATION
        self.multiple_validation = MULTIPLE_VALIDATION
        self.trusted_dns_servers = TRUSTED_DNS_SERVERS
        
        # Runtime data
        self.arp_cache = {}
        self.confidence_scores = defaultdict(int)
        self.blacklisted_macs = set()
        self.validation_history = defaultdict(list)
        self.gateway_monitor_active = False
        
        # Load configuration
        self.load_config()
        
        print(f"🔒 Secure ARP Client initialized")
        print(f"   Interface: {self.interface}")
        print(f"   Validation threshold: {self.validation_threshold}")
        print(f"   DNS validation: {'Enabled' if self.dns_validation else 'Disabled'}")
        print(f"   Cache timeout: {self.cache_timeout}s")
        
    def load_config(self):
        """Load configuration"""
        default_config = {
            "validation_threshold": 3,
            "cache_timeout": 300,
            "gateway_protection": True,
            "multiple_validation": True,
            "dns_validation": True,
            "trusted_dns_servers": ["8.8.8.8", "1.1.1.1"],
            "enable_blacklist": True,
            "log_suspicious_activity": True
        }
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config=None):
        """Save configuration"""
        if config is None:
            config = self.config
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def get_gateway_ip(self):
        """Get default gateway IP"""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split()[2]
        except:
            pass
        return None
    
    def calculate_confidence_score(self, ip, mac, validation_methods):
        """Calculate confidence score for IP-MAC mapping"""
        score = 0
        max_score = 100
        
        # Base score for ARP response
        score += 20
        
        # Bonus for multiple validations
        if validation_methods.get('multiple_arp', 0) >= 2:
            score += 25
        
        # Bonus for DNS validation
        if validation_methods.get('dns_validation', False):
            score += 25
        
        # Bonus for consistent responses
        if validation_methods.get('consistency_check', False):
            score += 20
        
        # Bonus for gateway validation
        if ip == self.gateway_ip and validation_methods.get('gateway_validation', False):
            score += 10
        
        return min(score, max_score)
    
    def validate_arp_response(self, ip, mac, multiple_checks=True):
        """Validate ARP response with multiple methods"""
        validation_methods = {}
        
        if multiple_checks and self.config.get('multiple_validation', True):
            # Send multiple ARP requests and check consistency
            responses = []
            for i in range(3):
                resp = self.send_arp_request(ip, timeout=2)
                if resp:
                    responses.append(resp)
                time.sleep(0.5)
            
            # Check if all responses are consistent
            if len(responses) >= 2:
                macs = [r.hwsrc for r in responses]
                if len(set(macs)) == 1:  # All same MAC
                    validation_methods['multiple_arp'] = len(responses)
                    validation_methods['consistency_check'] = True
                else:
                    print(f"⚠️  Inconsistent ARP responses for {ip}: {set(macs)}")
                    return False, validation_methods
        
        # DNS validation (if hostname available)
        if self.config.get('dns_validation', True):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                # Additional DNS-based validation could be implemented here
                validation_methods['dns_validation'] = True
            except:
                pass
        
        # Gateway-specific validation
        if ip == self.gateway_ip:
            validation_methods['gateway_validation'] = True
        
        return True, validation_methods
    
    def send_arp_request(self, target_ip, timeout=3):
        """Send ARP request and return response"""
        try:
            # Create ARP request
            arp_request = ARP(pdst=target_ip)
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether_frame / arp_request
            
            # Send and receive
            result = srp(packet, timeout=timeout, verbose=False, iface=self.interface)[0]
            
            if result:
                self.stats['arp_requests_sent'] += 1
                return result[0][1][ARP]
            
        except Exception as e:
            print(f"ARP request failed for {target_ip}: {e}")
        
        return None
    
    def secure_arp_resolve(self, ip):
        """Securely resolve IP to MAC with validation"""
        current_time = datetime.now()
        
        # Check if we have a cached entry
        if ip in self.secure_arp_cache:
            mac, timestamp, confidence, validation_count = self.secure_arp_cache[ip]
            age = (current_time - timestamp).total_seconds()
            
            # Return cached entry if it's still valid and trusted
            if age < self.cache_timeout and confidence >= 70:
                return mac
        
        print(f"🔍 Performing secure ARP resolution for {ip}")
        
        # Send ARP request
        arp_response = self.send_arp_request(ip)
        if not arp_response:
            print(f"❌ No ARP response for {ip}")
            return None
        
        mac = arp_response.hwsrc
        
        # Check blacklist
        if mac in self.blacklisted_macs:
            print(f"🚫 MAC {mac} is blacklisted, blocking resolution for {ip}")
            self.stats['spoofing_attempts_blocked'] += 1
            return None
        
        # Validate the response
        is_valid, validation_methods = self.validate_arp_response(ip, mac)
        if not is_valid:
            print(f"❌ ARP validation failed for {ip} -> {mac}")
            self.blacklisted_macs.add(mac)
            return None
        
        # Calculate confidence score
        confidence = self.calculate_confidence_score(ip, mac, validation_methods)
        validation_count = 1
        
        # Update cache
        self.secure_arp_cache[ip] = (mac, current_time, confidence, validation_count)
        self.stats['validations_performed'] += 1
        
        print(f"✅ Secure ARP resolution: {ip} -> {mac} (confidence: {confidence}%)")
        
        if confidence >= 70:
            self.stats['secure_resolutions'] += 1
            return mac
        else:
            print(f"⚠️  Low confidence score ({confidence}%), not returning MAC")
            return None
    
    def validate_gateway_continuously(self):
        """Continuously validate gateway MAC address"""
        if not self.gateway_ip:
            return
        
        while True:
            try:
                # Resolve gateway MAC
                gateway_mac = self.secure_arp_resolve(self.gateway_ip)
                
                if gateway_mac:
                    if self.gateway_mac is None:
                        self.gateway_mac = gateway_mac
                        self.gateway_validated = True
                        print(f"🛡️  Gateway validated: {self.gateway_ip} -> {gateway_mac}")
                    elif self.gateway_mac != gateway_mac:
                        print(f"🚨 GATEWAY MAC CHANGED!")
                        print(f"   Previous: {self.gateway_mac}")
                        print(f"   Current:  {gateway_mac}")
                        print(f"   This may indicate ARP poisoning!")
                        
                        # Additional validation for gateway change
                        time.sleep(5)
                        recheck_mac = self.secure_arp_resolve(self.gateway_ip)
                        if recheck_mac == gateway_mac:
                            print(f"⚠️  Gateway MAC change confirmed")
                            self.gateway_mac = gateway_mac
                        else:
                            print(f"🚫 Gateway MAC change not consistent, possible attack")
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Error in gateway validation: {e}")
                time.sleep(60)
    
    def monitor_arp_traffic(self):
        """Monitor ARP traffic for suspicious activity"""
        def packet_handler(packet):
            if packet.haslayer(ARP):
                arp = packet[ARP]
                if arp.op == 2:  # ARP reply
                    src_ip = arp.psrc
                    src_mac = arp.hwsrc
                    
                    # Check if this contradicts our secure cache
                    if src_ip in self.secure_arp_cache:
                        cached_mac, _, confidence, _ = self.secure_arp_cache[src_ip]
                        if cached_mac != src_mac and confidence >= 70:
                            print(f"🚨 Suspicious ARP reply detected!")
                            print(f"   IP: {src_ip}")
                            print(f"   Cached MAC: {cached_mac}")
                            print(f"   Reply MAC:  {src_mac}")
                            
                            # Add suspicious MAC to blacklist
                            self.blacklisted_macs.add(src_mac)
        
        print("🔍 Starting ARP traffic monitoring...")
        sniff(iface=self.interface, filter="arp", prn=packet_handler)
    
    def set_static_arp_entries(self):
        """Set static ARP entries for secure cache"""
        print("🔒 Setting static ARP entries from secure cache...")
        
        for ip, (mac, timestamp, confidence, _) in self.secure_arp_cache.items():
            if confidence >= 80:  # Only set high-confidence entries
                try:
                    subprocess.run(['sudo', 'arp', '-s', ip, mac], 
                                 capture_output=True, check=True)
                    print(f"✅ Set static ARP: {ip} -> {mac}")
                except subprocess.CalledProcessError as e:
                    print(f"❌ Failed to set static ARP for {ip}: {e}")
    
    def clear_system_arp_cache(self):
        """Clear system ARP cache to force re-resolution"""
        try:
            subprocess.run(['sudo', 'ip', 'neigh', 'flush', 'all'], check=True)
            print("✅ System ARP cache cleared")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to clear ARP cache: {e}")
    
    def get_statistics(self):
        """Get client statistics"""
        return {
            **self.stats,
            "secure_cache_entries": len(self.secure_arp_cache),
            "blacklisted_macs": len(self.blacklisted_macs),
            "gateway_validated": self.gateway_validated,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac
        }
    
    def interactive_resolve(self, ip):
        """Interactive IP resolution with detailed output"""
        print(f"\n🔍 Resolving {ip} with security validation...")
        
        start_time = time.time()
        mac = self.secure_arp_resolve(ip)
        end_time = time.time()
        
        print(f"⏱️  Resolution time: {end_time - start_time:.2f} seconds")
        
        if mac:
            print(f"✅ Secure resolution successful: {ip} -> {mac}")
            
            # Show cache info
            if ip in self.secure_arp_cache:
                _, timestamp, confidence, validation_count = self.secure_arp_cache[ip]
                print(f"📊 Confidence: {confidence}%, Validations: {validation_count}")
                print(f"🕒 Cached at: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"❌ Secure resolution failed for {ip}")
        
        return mac
    
    def start_protection(self):
        """Start comprehensive protection"""
        print("🛡️  Starting Secure ARP Client protection...")
        
        # Clear system cache to start fresh
        self.clear_system_arp_cache()
        
        # Start gateway validation thread
        if self.config.get('gateway_protection', True):
            gateway_thread = threading.Thread(target=self.validate_gateway_continuously)
            gateway_thread.daemon = True
            gateway_thread.start()
        
        # Start ARP monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_arp_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        print("✅ Protection started. Use interactive mode or API calls for secure resolution.")
        
        try:
            # Interactive mode
            while True:
                cmd = input("\nSecure ARP> ").strip().split()
                if not cmd:
                    continue
                
                if cmd[0] == 'resolve':
                    if len(cmd) > 1:
                        self.interactive_resolve(cmd[1])
                    else:
                        print("Usage: resolve <IP>")
                
                elif cmd[0] == 'stats':
                    stats = self.get_statistics()
                    print(json.dumps(stats, indent=2))
                
                elif cmd[0] == 'cache':
                    print("\n📋 Secure ARP Cache:")
                    for ip, (mac, timestamp, confidence, validations) in self.secure_arp_cache.items():
                        age = (datetime.now() - timestamp).total_seconds()
                        print(f"  {ip} -> {mac} (confidence: {confidence}%, age: {age:.0f}s)")
                
                elif cmd[0] == 'blacklist':
                    print(f"\n🚫 Blacklisted MACs: {list(self.blacklisted_macs)}")
                
                elif cmd[0] == 'static':
                    self.set_static_arp_entries()
                
                elif cmd[0] == 'clear':
                    self.clear_system_arp_cache()
                
                elif cmd[0] == 'help':
                    print("""
Available commands:
  resolve <IP>  - Securely resolve IP to MAC
  stats         - Show statistics
  cache         - Show secure cache
  blacklist     - Show blacklisted MACs
  static        - Set static ARP entries
  clear         - Clear system ARP cache
  help          - Show this help
  quit/exit     - Exit program
                    """)
                
                elif cmd[0] in ['quit', 'exit']:
                    break
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print("\n👋 Shutting down Secure ARP Client...")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure ARP Client")
    parser.add_argument("-i", "--interface", default="wlo1",
                       help="Network interface to use")
    parser.add_argument("-c", "--config", default="secure_arp_config.json",
                       help="Configuration file")
    parser.add_argument("--resolve", help="Resolve specific IP")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    
    args = parser.parse_args()
    
    client = SecureARPClient(args.interface, args.config)
    
    if args.resolve:
        mac = client.interactive_resolve(args.resolve)
        if mac:
            print(f"Result: {args.resolve} -> {mac}")
        else:
            print(f"Failed to resolve {args.resolve}")
        return
    
    if args.stats:
        stats = client.get_statistics()
        print(json.dumps(stats, indent=2))
        return
    
    # Start interactive protection mode
    client.start_protection()

if __name__ == "__main__":
    main() 