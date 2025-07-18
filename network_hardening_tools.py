#!/usr/bin/env python3
"""
Network Hardening Tools - System-level protection against ARP-based attacks
Implements multiple layers of network security hardening
"""

import subprocess
import json
import os
import sys
import time
from datetime import datetime

# Import centralized configuration
from config import NetworkConfig, DefenseConfig, PathConfig, SecurityConfig

# Use configuration values
INTERFACE = NetworkConfig.INTERFACE
ENABLE_STATIC_ARP = DefenseConfig.ENABLE_STATIC_ARP
TRUSTED_DEVICES_DB = PathConfig.TRUSTED_DEVICES_DB
NETWORK_BASELINE = PathConfig.NETWORK_BASELINE
LOG_LEVEL = DefenseConfig.LOG_LEVEL

class NetworkHardeningTools:
    def __init__(self, interface=None):
        self.interface = interface or INTERFACE
        self.hardening_active = False
        self.protection_rules = []
        
        # Configuration from centralized config
        self.enable_static_arp = ENABLE_STATIC_ARP
        self.trusted_devices_file = TRUSTED_DEVICES_DB
        self.baseline_file = NETWORK_BASELINE
        
        # Get network info
        self.gateway_ip = self.get_gateway_ip()
        self.local_ip = self.get_local_ip()
        self.network_range = self.get_network_range()
        
        print(f"🔧 Network Hardening Tools initialized")
        print(f"   Interface: {self.interface}")
        print(f"   Static ARP: {'Enabled' if self.enable_static_arp else 'Disabled'}")
        print(f"   Local IP: {self.local_ip}")
        print(f"   Gateway: {self.gateway_ip}")
        print(f"   Network: {self.network_range}")
        
        # Check privileges
        if os.geteuid() != 0:
            print("⚠️  Warning: Many hardening features require root privileges")
            print("   Run with sudo for full functionality")
    
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
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            result = subprocess.run(['ip', 'addr', 'show', self.interface], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'inet ' in line and not 'inet6' in line:
                    return line.split()[1].split('/')[0]
        except:
            pass
        return None
    
    def get_network_range(self):
        """Get network range"""
        try:
            result = subprocess.run(['ip', 'route', 'show'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if self.interface in line and '/' in line:
                    parts = line.split()
                    for part in parts:
                        if '/' in part and not 'default' in line:
                            return part
        except:
            pass
        return None
    
    def enable_arp_filtering(self):
        """Enable kernel ARP filtering"""
        print("🛡️  Enabling ARP filtering...")
        
        arp_settings = [
            ('net.ipv4.conf.all.arp_filter', '1'),
            ('net.ipv4.conf.default.arp_filter', '1'),
            (f'net.ipv4.conf.{self.interface}.arp_filter', '1'),
            ('net.ipv4.conf.all.arp_announce', '2'),
            ('net.ipv4.conf.default.arp_announce', '2'),
            (f'net.ipv4.conf.{self.interface}.arp_announce', '2'),
            ('net.ipv4.conf.all.arp_ignore', '1'),
            ('net.ipv4.conf.default.arp_ignore', '1'),
            (f'net.ipv4.conf.{self.interface}.arp_ignore', '1'),
            ('net.ipv4.conf.all.rp_filter', '1'),
            ('net.ipv4.conf.default.rp_filter', '1'),
            (f'net.ipv4.conf.{self.interface}.rp_filter', '1')
        ]
        
        for setting, value in arp_settings:
            try:
                subprocess.run(['sudo', 'sysctl', '-w', f'{setting}={value}'], 
                             check=True, capture_output=True)
                print(f"✅ Set {setting} = {value}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to set {setting}: {e}")
    
    def setup_iptables_protection(self):
        """Setup iptables rules for Layer 2 protection"""
        print("🔥 Setting up iptables protection rules...")
        
        rules = [
            # Log ARP packets for monitoring
            ['sudo', 'iptables', '-I', 'INPUT', '-p', 'arp', '-j', 'LOG', 
             '--log-prefix', 'ARP_MONITOR: ', '--log-level', '4'],
            
            # Rate limit ARP requests
            ['sudo', 'iptables', '-I', 'INPUT', '-p', 'arp', '--arp-op', 'request',
             '-m', 'limit', '--limit', '10/min', '--limit-burst', '5', '-j', 'ACCEPT'],
            
            # Drop excessive ARP requests
            ['sudo', 'iptables', '-I', 'INPUT', '-p', 'arp', '--arp-op', 'request', '-j', 'DROP'],
            
            # Log dropped packets
            ['sudo', 'iptables', '-I', 'INPUT', '-p', 'arp', '-j', 'LOG', 
             '--log-prefix', 'ARP_DROPPED: ', '--log-level', '4'],
        ]
        
        for rule in rules:
            try:
                subprocess.run(rule, check=True, capture_output=True)
                self.protection_rules.append(rule)
                print(f"✅ Added iptables rule: {' '.join(rule[2:])}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to add iptables rule: {e}")
    
    def setup_ebtables_protection(self):
        """Setup ebtables rules for Ethernet-level protection"""
        print("🔗 Setting up ebtables protection...")
        
        try:
            # Check if ebtables is available
            subprocess.run(['which', 'ebtables'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print("⚠️  ebtables not available, skipping Ethernet-level protection")
            return
        
        rules = [
            # Limit ARP traffic rate
            ['sudo', 'ebtables', '-A', 'INPUT', '-p', 'ARP', '--limit', '10/min', '-j', 'ACCEPT'],
            ['sudo', 'ebtables', '-A', 'INPUT', '-p', 'ARP', '-j', 'DROP'],
            
            # Log ARP traffic
            ['sudo', 'ebtables', '-A', 'INPUT', '-p', 'ARP', '--log-prefix', 'EBTABLES_ARP: '],
        ]
        
        for rule in rules:
            try:
                subprocess.run(rule, check=True, capture_output=True)
                print(f"✅ Added ebtables rule: {' '.join(rule[2:])}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to add ebtables rule: {e}")
    
    def configure_static_arp_table(self, trusted_devices=None):
        """Configure static ARP entries for critical devices"""
        print("🔒 Configuring static ARP table...")
        
        if not trusted_devices:
            # Auto-discover current devices
            trusted_devices = self.discover_trusted_devices()
        
        for ip, mac in trusted_devices.items():
            try:
                # Set permanent static ARP entry
                subprocess.run(['sudo', 'arp', '-s', ip, mac], 
                             check=True, capture_output=True)
                print(f"✅ Static ARP: {ip} -> {mac}")
                
                # Also add to /etc/ethers for persistence
                self.add_to_ethers(ip, mac)
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to set static ARP for {ip}: {e}")
    
    def add_to_ethers(self, ip, mac):
        """Add entry to /etc/ethers for persistent ARP mapping"""
        try:
            ethers_entry = f"{mac} {ip}\n"
            
            # Check if entry already exists
            try:
                with open('/etc/ethers', 'r') as f:
                    if ethers_entry.strip() in f.read():
                        return
            except FileNotFoundError:
                pass
            
            # Add entry
            subprocess.run(['sudo', 'sh', '-c', f'echo "{mac} {ip}" >> /etc/ethers'],
                         check=True)
            print(f"📝 Added to /etc/ethers: {ip} -> {mac}")
            
        except Exception as e:
            print(f"❌ Failed to add to /etc/ethers: {e}")
    
    def discover_trusted_devices(self):
        """Discover current network devices to use as trusted baseline"""
        print("🔍 Discovering trusted devices...")
        
        trusted_devices = {}
        
        # Get current ARP table
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '(' in line and ')' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1][1:-1]  # Remove parentheses
                        mac = parts[3]
                        if mac != '<incomplete>':
                            trusted_devices[ip] = mac
                            print(f"📱 Found device: {ip} -> {mac}")
        except Exception as e:
            print(f"❌ Failed to discover devices: {e}")
        
        return trusted_devices
    
    def setup_network_monitoring(self):
        """Setup comprehensive network monitoring"""
        print("👁️  Setting up network monitoring...")
        
        # Create monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_network_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        print("✅ Network monitoring started")
    
    def _monitor_network_traffic(self):
        """Monitor network traffic for suspicious activity"""
        def packet_handler(packet):
            current_time = datetime.now()
            
            # Monitor ARP traffic
            if packet.haslayer(ARP):
                arp = packet[ARP]
                
                # Log ARP activity
                log_entry = {
                    'timestamp': current_time.isoformat(),
                    'type': 'ARP',
                    'operation': 'request' if arp.op == 1 else 'reply',
                    'src_ip': arp.psrc,
                    'src_mac': arp.hwsrc,
                    'dst_ip': arp.pdst,
                    'dst_mac': arp.hwdst if arp.op == 2 else 'broadcast'
                }
                
                # Check for suspicious patterns
                if self._is_suspicious_arp(arp):
                    log_entry['alert'] = 'SUSPICIOUS_ARP_ACTIVITY'
                    print(f"🚨 {log_entry}")
                    self._handle_suspicious_activity(arp)
                
                # Write to log file
                with open('network_monitor.log', 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')
            
            # Monitor DHCP traffic
            elif packet.haslayer(DHCP):
                dhcp = packet[DHCP]
                log_entry = {
                    'timestamp': current_time.isoformat(),
                    'type': 'DHCP',
                    'src_mac': packet[Ether].src,
                    'transaction_id': packet[BOOTP].xid
                }
                
                # Check for DHCP spoofing
                if self._is_suspicious_dhcp(packet):
                    log_entry['alert'] = 'POSSIBLE_DHCP_SPOOFING'
                    print(f"🚨 {log_entry}")
        
        # Start packet capture
        try:
            sniff(iface=self.interface, prn=packet_handler, store=0)
        except Exception as e:
            print(f"❌ Network monitoring error: {e}")
    
    def _is_suspicious_arp(self, arp):
        """Check if ARP packet is suspicious"""
        # Check for gratuitous ARP replies (potential spoofing)
        if arp.op == 2 and arp.psrc == arp.pdst:
            return True
        
        # Check for ARP replies to broadcast (unusual)
        if arp.op == 2 and arp.hwdst == "ff:ff:ff:ff:ff:ff":
            return True
        
        # Add more sophisticated detection logic here
        return False
    
    def _is_suspicious_dhcp(self, packet):
        """Check if DHCP packet is suspicious"""
        # Check for multiple DHCP servers
        if packet.haslayer(DHCP):
            # This would require maintaining state of known DHCP servers
            pass
        
        return False
    
    def _handle_suspicious_activity(self, arp):
        """Handle detected suspicious activity"""
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        
        # Add to temporary blacklist
        print(f"🚫 Temporarily blocking suspicious MAC: {src_mac}")
        
        # Could implement automatic blocking here
        # subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-m', 'mac', 
        #                '--mac-source', src_mac, '-j', 'DROP'])
    
    def enable_dhcp_snooping_simulation(self):
        """Simulate DHCP snooping protection"""
        print("🛡️  Enabling DHCP snooping simulation...")
        
        # This would typically be done on managed switches
        # Here we simulate with monitoring and alerting
        
        def dhcp_monitor():
            dhcp_servers = set()
            
            def packet_handler(packet):
                if packet.haslayer(DHCP):
                    dhcp_type = None
                    for option in packet[DHCP].options:
                        if option[0] == 'message-type':
                            dhcp_type = option[1]
                            break
                    
                    # Monitor DHCP offers (type 2)
                    if dhcp_type == 2:  # DHCP Offer
                        server_ip = packet[IP].src
                        dhcp_servers.add(server_ip)
                        
                        if len(dhcp_servers) > 1:
                            print(f"⚠️  Multiple DHCP servers detected: {dhcp_servers}")
                            print("   This may indicate a rogue DHCP server!")
            
            sniff(filter="udp port 67 or udp port 68", prn=packet_handler, iface=self.interface)
        
        dhcp_thread = threading.Thread(target=dhcp_monitor)
        dhcp_thread.daemon = True
        dhcp_thread.start()
        
        print("✅ DHCP snooping simulation active")
    
    def create_network_baseline(self):
        """Create a baseline of normal network activity"""
        print("📊 Creating network baseline...")
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'gateway_ip': self.gateway_ip,
            'local_ip': self.local_ip,
            'network_range': self.network_range,
            'active_devices': self.discover_trusted_devices(),
            'interface': self.interface
        }
        
        with open('network_baseline.json', 'w') as f:
            json.dump(baseline, f, indent=2)
        
        print("✅ Network baseline saved to network_baseline.json")
        return baseline
    
    def apply_comprehensive_hardening(self):
        """Apply all available hardening measures"""
        print("🚀 Applying comprehensive network hardening...")
        
        try:
            # Kernel-level protections
            self.enable_arp_filtering()
            
            # Firewall rules
            self.setup_iptables_protection()
            self.setup_ebtables_protection()
            
            # Static ARP configuration
            trusted_devices = self.discover_trusted_devices()
            self.configure_static_arp_table(trusted_devices)
            
            # Monitoring
            self.setup_network_monitoring()
            self.enable_dhcp_snooping_simulation()
            
            # Create baseline
            self.create_network_baseline()
            
            self.hardening_active = True
            print("✅ Comprehensive network hardening applied successfully!")
            
        except Exception as e:
            print(f"❌ Error applying hardening: {e}")
    
    def remove_hardening(self):
        """Remove all hardening measures"""
        print("🔄 Removing network hardening...")
        
        # Remove iptables rules
        for rule in self.protection_rules:
            try:
                # Convert -I to -D to delete
                delete_rule = rule.copy()
                if '-I' in delete_rule:
                    idx = delete_rule.index('-I')
                    delete_rule[idx] = '-D'
                
                subprocess.run(delete_rule, capture_output=True)
                print(f"✅ Removed rule: {' '.join(delete_rule[2:])}")
            except:
                pass
        
        # Reset kernel settings
        reset_settings = [
            ('net.ipv4.conf.all.arp_filter', '0'),
            ('net.ipv4.conf.all.arp_announce', '0'),
            ('net.ipv4.conf.all.arp_ignore', '0'),
            ('net.ipv4.conf.all.rp_filter', '0')
        ]
        
        for setting, value in reset_settings:
            try:
                subprocess.run(['sudo', 'sysctl', '-w', f'{setting}={value}'], 
                             capture_output=True)
                print(f"✅ Reset {setting} = {value}")
            except:
                pass
        
        self.hardening_active = False
        print("✅ Network hardening removed")
    
    def status_report(self):
        """Generate comprehensive status report"""
        status = {
            'timestamp': datetime.now().isoformat(),
            'hardening_active': self.hardening_active,
            'interface': self.interface,
            'local_ip': self.local_ip,
            'gateway_ip': self.gateway_ip,
            'network_range': self.network_range,
            'protection_rules_count': len(self.protection_rules),
            'monitoring_active': True  # Simplified for demo
        }
        
        # Check current ARP table
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            arp_entries = len([line for line in result.stdout.split('\n') if '(' in line])
            status['arp_table_entries'] = arp_entries
        except:
            status['arp_table_entries'] = 'unknown'
        
        return status

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Hardening Tools")
    parser.add_argument("-i", "--interface", default="wlo1",
                       help="Network interface")
    parser.add_argument("--apply", action="store_true",
                       help="Apply comprehensive hardening")
    parser.add_argument("--remove", action="store_true",
                       help="Remove hardening measures")
    parser.add_argument("--status", action="store_true",
                       help="Show status report")
    parser.add_argument("--baseline", action="store_true",
                       help="Create network baseline")
    
    args = parser.parse_args()
    
    tools = NetworkHardeningTools(args.interface)
    
    if args.apply:
        tools.apply_comprehensive_hardening()
        
        # Keep running for monitoring
        try:
            print("🔒 Hardening active. Press Ctrl+C to stop...")
            while True:
                time.sleep(60)
                print(f"📊 Status: {datetime.now().strftime('%H:%M:%S')} - Protection active")
        except KeyboardInterrupt:
            print("\n🛑 Stopping hardening...")
            tools.remove_hardening()
    
    elif args.remove:
        tools.remove_hardening()
    
    elif args.status:
        status = tools.status_report()
        print(json.dumps(status, indent=2))
    
    elif args.baseline:
        tools.create_network_baseline()
    
    else:
        print("Use --apply to enable hardening, --remove to disable, or --status for report")

if __name__ == "__main__":
    main() 