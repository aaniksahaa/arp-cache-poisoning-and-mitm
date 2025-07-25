#!/usr/bin/env python3
"""
ARP Defense System
Comprehensive protection against ARP poisoning/spoofing attacks

Features:
- Real-time ARP monitoring and attack detection
- Automatic ARP cache restoration 
- Static ARP entries for critical devices
- Gratuitous ARP broadcasting for legitimate mappings
- Multi-layered defense mechanisms
- Real-time alerts and logging
"""

from scapy.all import *
import os
import sys
import time
import json
import signal
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
import ipaddress
import re
from colorama import Fore, Back, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class ARPDefenseSystem:
    def __init__(self, interface=None, config_file="arp_defense_config.json"):
        self.interface = interface or self.get_default_interface()
        self.config_file = config_file
        
        # Network information
        self.our_ip = get_if_addr(self.interface)
        self.our_mac = get_if_hwaddr(self.interface)
        self.network_range = self.get_network_range()
        self.gateway_ip = self.get_gateway_ip()
        
        # ARP monitoring data
        self.legitimate_arp_table = {}  # IP -> MAC mapping
        self.arp_history = defaultdict(deque)  # Track ARP changes over time
        self.attack_history = defaultdict(list)  # Track detected attacks
        self.suspicious_macs = set()  # MACs that have been seen doing suspicious things
        
        # Defense configuration
        self.monitoring_active = False
        self.defense_active = False
        self.static_entries_set = False
        
        # Statistics
        self.stats = {
            'packets_monitored': 0,
            'attacks_detected': 0,
            'restorations_performed': 0,
            'gratuitous_arps_sent': 0,
            'start_time': time.time()
        }
        
        # Critical devices (will be protected with static ARP entries)
        self.critical_devices = set()
        
        # Setup logging
        self.setup_logging()
        
        # Load configuration
        self.load_configuration()
        
        print(f"\n{Fore.GREEN}🛡️  ARP Defense System Initialized{Style.RESET_ALL}")
        print(f"   Interface: {self.interface}")
        print(f"   Our IP: {self.our_ip}")
        print(f"   Our MAC: {self.our_mac}")
        print(f"   Network: {self.network_range}")
        print(f"   Gateway: {self.gateway_ip}")
    
    def setup_logging(self):
        """Setup comprehensive logging system"""
        # Create logs directory if it doesn't exist
        os.makedirs('defense_logs', exist_ok=True)
        
        # Setup file handler with rotation
        log_filename = f"defense_logs/arp_defense_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"🛡️  ARP Defense System starting - Log file: {log_filename}")
    
    def get_default_interface(self):
        """Get the default network interface"""
        try:
            # Get default route interface
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Parse: default via 192.168.1.1 dev wlan0 proto dhcp metric 600
                match = re.search(r'dev\s+(\w+)', result.stdout)
                if match:
                    return match.group(1)
            
            # Fallback to first non-loopback interface
            interfaces = get_if_list()
            for iface in interfaces:
                if iface != 'lo' and get_if_addr(iface) != '127.0.0.1':
                    return iface
                    
        except Exception as e:
            self.logger.warning(f"Could not auto-detect interface: {e}")
        
        return 'eth0'  # Final fallback
    
    def get_network_range(self):
        """Get the network range for our interface"""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'dev', self.interface], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '/' in line and 'scope link' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if match:
                        return match.group(1)
        except:
            pass
        
        # Fallback: calculate from IP
        try:
            network = ipaddress.IPv4Network(f"{self.our_ip}/24", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"
    
    def get_gateway_ip(self):
        """Get the default gateway IP"""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    return match.group(1)
        except:
            pass
        
        return "192.168.1.1"  # Common default
    
    def load_configuration(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.legitimate_arp_table = config.get('legitimate_arp_table', {})
                    self.critical_devices = set(config.get('critical_devices', []))
                    if self.gateway_ip not in self.critical_devices:
                        self.critical_devices.add(self.gateway_ip)
                    
                    self.logger.info(f"✅ Loaded configuration: {len(self.legitimate_arp_table)} known devices")
            else:
                # Add gateway as critical device by default
                self.critical_devices.add(self.gateway_ip)
                self.logger.info("📝 No existing configuration found, will learn network")
                
        except Exception as e:
            self.logger.error(f"❌ Error loading configuration: {e}")
    
    def save_configuration(self):
        """Save current configuration to file"""
        try:
            config = {
                'legitimate_arp_table': self.legitimate_arp_table,
                'critical_devices': list(self.critical_devices),
                'last_updated': datetime.now().isoformat(),
                'network_range': self.network_range,
                'gateway_ip': self.gateway_ip
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            self.logger.info(f"💾 Configuration saved: {len(self.legitimate_arp_table)} devices")
            
        except Exception as e:
            self.logger.error(f"❌ Error saving configuration: {e}")
    
    def discover_network_devices(self, timeout=30):
        """Discover legitimate devices on the network"""
        print(f"\n{Fore.CYAN}🔍 Discovering network devices...{Style.RESET_ALL}")
        print(f"   Network range: {self.network_range}")
        print(f"   Timeout: {timeout} seconds")
        
        discovered_devices = {}
        
        # Get current ARP table
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                # Parse: gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([a-fA-F0-9:]{17})', line)
                if match:
                    ip, mac = match.groups()
                    if ip != self.our_ip:  # Don't include ourselves
                        discovered_devices[ip] = mac.lower()
                        
        except Exception as e:
            self.logger.warning(f"Could not read system ARP table: {e}")
        
        # Perform network scan
        network = ipaddress.IPv4Network(self.network_range, strict=False)
        scan_count = 0
        
        # Calculate number of hosts (compatible with older Python versions)
        try:
            num_hosts = network.num_hosts
        except AttributeError:
            # For older Python versions, calculate manually
            num_hosts = 2**(32 - network.prefixlen) - 2
        
        print(f"   {Fore.YELLOW}Scanning {num_hosts} possible hosts...{Style.RESET_ALL}")
        
        for ip in network.hosts():
            if scan_count >= 254:  # Reasonable limit
                break
                
            ip_str = str(ip)
            if ip_str == self.our_ip:
                continue
                
            # Send ARP request
            try:
                response = sr1(ARP(op=1, pdst=ip_str), timeout=0.1, verbose=0)
                if response and response.haslayer(ARP):
                    mac = response[ARP].hwsrc.lower()
                    discovered_devices[ip_str] = mac
                    print(f"   {Fore.GREEN}✓{Style.RESET_ALL} Found: {ip_str} -> {mac}")
                    
            except Exception:
                pass
            
            scan_count += 1
            
            # Show progress every 50 hosts
            if scan_count % 50 == 0:
                print(f"   {Fore.BLUE}Progress: {scan_count}/{min(254, num_hosts)} hosts scanned{Style.RESET_ALL}")
        
        # Update legitimate ARP table
        for ip, mac in discovered_devices.items():
            if ip not in self.legitimate_arp_table:
                self.legitimate_arp_table[ip] = mac
                self.logger.info(f"📝 Learned legitimate mapping: {ip} -> {mac}")
        
        print(f"\n{Fore.GREEN}✅ Network discovery complete{Style.RESET_ALL}")
        print(f"   Total devices discovered: {len(discovered_devices)}")
        print(f"   Total known devices: {len(self.legitimate_arp_table)}")
        
        # Mark gateway and critical devices
        if self.gateway_ip in self.legitimate_arp_table:
            self.critical_devices.add(self.gateway_ip)
            print(f"   {Fore.YELLOW}🔒 Gateway marked as critical: {self.gateway_ip}{Style.RESET_ALL}")
        
        self.save_configuration()
    
    def set_static_arp_entries(self):
        """Set static ARP entries for critical devices"""
        if self.static_entries_set:
            return
            
        print(f"\n{Fore.CYAN}🔒 Setting static ARP entries for critical devices...{Style.RESET_ALL}")
        
        static_count = 0
        for ip in self.critical_devices:
            if ip in self.legitimate_arp_table:
                mac = self.legitimate_arp_table[ip]
                try:
                    # Add static ARP entry
                    cmd = f"arp -s {ip} {mac}"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        static_count += 1
                        print(f"   {Fore.GREEN}✓{Style.RESET_ALL} Static entry: {ip} -> {mac}")
                        self.logger.info(f"🔒 Static ARP entry set: {ip} -> {mac}")
                    else:
                        self.logger.warning(f"Failed to set static ARP entry for {ip}: {result.stderr}")
                        
                except Exception as e:
                    self.logger.error(f"Error setting static ARP entry for {ip}: {e}")
        
        self.static_entries_set = True
        print(f"   {Fore.GREEN}✅ {static_count} static ARP entries configured{Style.RESET_ALL}")
    
    def is_arp_poisoning_attempt(self, arp_packet):
        """Detect if an ARP packet is a poisoning attempt"""
        if not arp_packet.haslayer(ARP):
            return False, "Not an ARP packet"
        
        arp = arp_packet[ARP]
        
        # Only check ARP responses (replies)
        if arp.op != 2:
            return False, "Not an ARP response"
        
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()
        
        # Skip our own packets
        if src_mac == self.our_mac.lower():
            return False, "Our own packet"
        
        # Check if we know the legitimate MAC for this IP
        if src_ip in self.legitimate_arp_table:
            legitimate_mac = self.legitimate_arp_table[src_ip].lower()
            
            if src_mac != legitimate_mac:
                return True, f"MAC mismatch: {src_ip} claims to be {src_mac} but should be {legitimate_mac}"
        
        # Check for gratuitous ARP from unknown source
        if arp.psrc == arp.pdst and src_ip not in self.legitimate_arp_table:
            return True, f"Gratuitous ARP from unknown device: {src_ip} ({src_mac})"
        
        # Check if one MAC is claiming multiple IPs
        claiming_ips = []
        for ip, mac in self.legitimate_arp_table.items():
            if mac.lower() == src_mac and ip != src_ip:
                claiming_ips.append(ip)
        
        if claiming_ips:
            return True, f"MAC {src_mac} claiming multiple IPs: {src_ip} and {claiming_ips}"
        
        # Check for rapid ARP responses (possible ARP storm)
        current_time = time.time()
        self.arp_history[src_mac].append(current_time)
        
        # Keep only last 10 seconds of history
        while (self.arp_history[src_mac] and 
               current_time - self.arp_history[src_mac][0] > 10):
            self.arp_history[src_mac].popleft()
        
        # More than 20 ARP responses in 10 seconds is suspicious
        if len(self.arp_history[src_mac]) > 20:
            return True, f"ARP flooding: {src_mac} sent {len(self.arp_history[src_mac])} responses in 10s"
        
        return False, "Legitimate ARP traffic"
    
    def handle_arp_attack(self, attack_info, arp_packet):
        """Handle detected ARP attack"""
        arp = arp_packet[ARP]
        attacker_ip = arp.psrc
        attacker_mac = arp.hwsrc.lower()
        
        # Record the attack
        attack_record = {
            'timestamp': datetime.now().isoformat(),
            'attacker_ip': attacker_ip,
            'attacker_mac': attacker_mac,
            'attack_type': attack_info,
            'target_ip': arp.pdst if arp.pdst != arp.psrc else 'gratuitous'
        }
        
        self.attack_history[attacker_mac].append(attack_record)
        self.suspicious_macs.add(attacker_mac)
        self.stats['attacks_detected'] += 1
        
        # Alert
        print(f"\n{Fore.RED}🚨 ARP ATTACK DETECTED! 🚨{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}Time: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
        print(f"   {Fore.RED}Attacker IP: {attacker_ip}{Style.RESET_ALL}")
        print(f"   {Fore.RED}Attacker MAC: {attacker_mac}{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}Attack Type: {attack_info}{Style.RESET_ALL}")
        
        self.logger.critical(f"🚨 ARP ATTACK: {attacker_ip} ({attacker_mac}) - {attack_info}")
        
        # Immediate response
        self.restore_legitimate_arp_entries()
        self.send_gratuitous_arp_responses()
        
        # Block attacker if possible
        self.block_attacker(attacker_mac)
    
    def restore_legitimate_arp_entries(self):
        """Restore legitimate ARP entries"""
        restored_count = 0
        
        for ip, legitimate_mac in self.legitimate_arp_table.items():
            try:
                # Force update ARP entry
                cmd = f"arp -d {ip} 2>/dev/null; arp -s {ip} {legitimate_mac}"
                subprocess.run(cmd, shell=True, capture_output=True)
                restored_count += 1
                
            except Exception as e:
                self.logger.error(f"Failed to restore ARP entry for {ip}: {e}")
        
        if restored_count > 0:
            self.stats['restorations_performed'] += restored_count
            self.logger.info(f"🔧 Restored {restored_count} ARP entries")
    
    def send_gratuitous_arp_responses(self):
        """Send gratuitous ARP responses to announce legitimate mappings"""
        sent_count = 0
        failed_count = 0
        
        for ip, mac in self.legitimate_arp_table.items():
            if ip == self.our_ip:  # Don't send for ourselves
                continue
                
            try:
                # Send gratuitous ARP (reply)
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,  # ARP reply
                    psrc=ip,
                    pdst=ip,
                    hwsrc=mac,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                
                sendp(pkt, iface=self.interface, verbose=0)
                sent_count += 1
                
            except PermissionError:
                failed_count += 1
                if failed_count == 1:  # Only log once to avoid spam
                    self.logger.warning(f"⚠️ Permission denied sending gratuitous ARPs - need root privileges or CAP_NET_RAW")
            except Exception as e:
                failed_count += 1
                if failed_count <= 3:  # Only log first few errors
                    self.logger.error(f"Failed to send gratuitous ARP for {ip}: {e}")
        
        if sent_count > 0:
            self.stats['gratuitous_arps_sent'] += sent_count
            self.logger.info(f"📡 Sent {sent_count} gratuitous ARP responses")
        elif failed_count > 0:
            self.logger.warning(f"⚠️ Failed to send {failed_count} gratuitous ARPs - check permissions")
    
    def block_attacker(self, attacker_mac):
        """Block attacker using iptables (if running as root)"""
        try:
            # Try to block using ebtables (Ethernet bridge tables)
            cmd = f"ebtables -A INPUT -s {attacker_mac} -j DROP 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                self.logger.info(f"🚫 Blocked attacker MAC: {attacker_mac}")
                print(f"   {Fore.GREEN}✓{Style.RESET_ALL} Blocked attacker MAC: {attacker_mac}")
            else:
                self.logger.warning(f"Could not block attacker {attacker_mac} - may need root privileges")
                
        except Exception as e:
            self.logger.warning(f"Could not block attacker {attacker_mac}: {e}")
    
    def arp_monitor_callback(self, packet):
        """Callback function for ARP packet monitoring"""
        try:
            self.stats['packets_monitored'] += 1
            
            # Check for ARP poisoning
            is_attack, attack_info = self.is_arp_poisoning_attempt(packet)
            
            if is_attack:
                self.handle_arp_attack(attack_info, packet)
            else:
                # Learn legitimate mappings
                if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
                    arp = packet[ARP]
                    src_ip = arp.psrc
                    src_mac = arp.hwsrc.lower()
                    
                    # Only learn if we don't know this mapping or it matches what we know
                    if (src_ip not in self.legitimate_arp_table or 
                        self.legitimate_arp_table[src_ip].lower() == src_mac):
                        
                        if src_ip not in self.legitimate_arp_table:
                            self.legitimate_arp_table[src_ip] = src_mac
                            self.logger.info(f"📝 Learned new legitimate mapping: {src_ip} -> {src_mac}")
                            
        except Exception as e:
            self.logger.error(f"Error in ARP monitor callback: {e}")
    
    def check_raw_socket_permissions(self):
        """Check if we have raw socket permissions"""
        try:
            # Try to create a raw socket
            import socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0806)  # ARP protocol
            sock.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return False
    
    def start_monitoring(self):
        """Start ARP monitoring"""
        if self.monitoring_active:
            return
        
        # Check permissions first
        if not self.check_raw_socket_permissions():
            print(f"\n{Fore.RED}❌ Raw socket permission denied{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}💡 Run with: sudo python3 arp_defense_system.py{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}💡 Or add CAP_NET_RAW capability{Style.RESET_ALL}")
            self.logger.error("❌ Cannot start ARP monitoring - insufficient permissions")
            return
        
        print(f"\n{Fore.GREEN}👁️  Starting ARP monitoring...{Style.RESET_ALL}")
        self.monitoring_active = True
        
        # Start packet sniffing in a separate thread
        def monitor_thread():
            try:
                sniff(iface=self.interface, 
                      filter="arp", 
                      prn=self.arp_monitor_callback,
                      stop_filter=lambda p: not self.monitoring_active)
            except PermissionError as e:
                self.logger.error(f"❌ Permission error in ARP monitoring: {e}")
                self.logger.error("💡 Make sure you're running as root or have CAP_NET_RAW capability")
                self.monitoring_active = False
            except Exception as e:
                self.logger.error(f"Error in ARP monitoring: {e}")
                self.monitoring_active = False
        
        self.monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("👁️  ARP monitoring started")
    
    def start_active_defense(self):
        """Start active defense mechanisms"""
        if self.defense_active:
            return
        
        print(f"\n{Fore.GREEN}🛡️  Starting active defense...{Style.RESET_ALL}")
        self.defense_active = True
        
        def defense_thread():
            defense_cycle = 0
            while self.defense_active:
                try:
                    defense_cycle += 1
                    
                    # Every cycle: restore ARP entries (most important)
                    self.restore_legitimate_arp_entries()
                    
                    # Every 3rd cycle: try to send gratuitous ARPs (less critical if it fails)
                    if defense_cycle % 3 == 0:
                        self.send_gratuitous_arp_responses()
                    
                    # Check for ARP table changes using system commands (fallback monitoring)
                    if not self.monitoring_active and defense_cycle % 5 == 0:
                        self.check_arp_table_changes()
                    
                    # Sleep for 10 seconds (more frequent checks)
                    time.sleep(10)
                    
                except Exception as e:
                    self.logger.error(f"Error in active defense: {e}")
                    
        self.defense_thread = threading.Thread(target=defense_thread, daemon=True)
        self.defense_thread.start()
        
        self.logger.info("🛡️  Active defense started")
    
    def check_arp_table_changes(self):
        """Fallback method to check ARP table using system commands"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode != 0:
                return
            
            current_arp_table = {}
            suspicious_found = False
            
            # Parse ARP table output
            import re
            for line in result.stdout.split('\n'):
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([a-fA-F0-9:]{17})', line)
                if match:
                    ip, mac = match.groups()
                    current_arp_table[ip] = mac.lower()
            
            # Check for suspicious entries
            for ip, current_mac in current_arp_table.items():
                if ip in self.legitimate_arp_table:
                    legitimate_mac = self.legitimate_arp_table[ip].lower()
                    if current_mac != legitimate_mac:
                        suspicious_found = True
                        self.logger.warning(f"🚨 ARP table anomaly detected: {ip} has MAC {current_mac} but should be {legitimate_mac}")
                        
                        # Record as attack
                        attack_record = {
                            'timestamp': datetime.now().isoformat(),
                            'attacker_ip': ip,
                            'attacker_mac': current_mac,
                            'attack_type': f"ARP table poisoning detected via system check",
                            'legitimate_mac': legitimate_mac
                        }
                        self.attack_history[current_mac].append(attack_record)
                        self.suspicious_macs.add(current_mac)
                        self.stats['attacks_detected'] += 1
            
            if suspicious_found:
                print(f"\n{Fore.RED}🚨 ARP table poisoning detected via system check!{Style.RESET_ALL}")
                print(f"   {Fore.YELLOW}Initiating ARP restoration...{Style.RESET_ALL}")
                
        except Exception as e:
            self.logger.debug(f"Error in ARP table check: {e}")
    
    def print_status(self):
        """Print current status and statistics"""
        runtime = time.time() - self.stats['start_time']
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"🛡️  ARP DEFENSE SYSTEM STATUS")
        print(f"{'='*70}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}⏱️  RUNTIME: {runtime:.1f} seconds{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}📊 STATISTICS:{Style.RESET_ALL}")
        print(f"   Packets monitored: {self.stats['packets_monitored']}")
        print(f"   Attacks detected: {self.stats['attacks_detected']}")
        print(f"   ARP restorations: {self.stats['restorations_performed']}")
        print(f"   Gratuitous ARPs sent: {self.stats['gratuitous_arps_sent']}")
        
        print(f"\n{Fore.BLUE}🔍 KNOWN DEVICES ({len(self.legitimate_arp_table)}):{Style.RESET_ALL}")
        for ip, mac in sorted(self.legitimate_arp_table.items()):
            critical = "🔒" if ip in self.critical_devices else "  "
            print(f"   {critical} {ip} -> {mac}")
        
        if self.suspicious_macs:
            print(f"\n{Fore.RED}🚨 SUSPICIOUS MACs ({len(self.suspicious_macs)}):{Style.RESET_ALL}")
            for mac in self.suspicious_macs:
                attack_count = len(self.attack_history[mac])
                print(f"   🚫 {mac} ({attack_count} attacks)")
        
        print(f"\n{Fore.GREEN}🛡️  DEFENSE STATUS:{Style.RESET_ALL}")
        print(f"   Monitoring: {'✅ Active' if self.monitoring_active else '❌ Inactive'}")
        print(f"   Active Defense: {'✅ Active' if self.defense_active else '❌ Inactive'}")
        print(f"   Static Entries: {'✅ Set' if self.static_entries_set else '❌ Not Set'}")
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    def cleanup(self):
        """Cleanup and shutdown"""
        print(f"\n{Fore.YELLOW}🧹 Shutting down ARP Defense System...{Style.RESET_ALL}")
        
        self.monitoring_active = False
        self.defense_active = False
        
        # Save configuration
        self.save_configuration()
        
        # Remove static ARP entries
        for ip in self.critical_devices:
            try:
                subprocess.run(f"arp -d {ip}", shell=True, capture_output=True)
            except:
                pass
        
        # Remove ebtables rules
        try:
            subprocess.run("ebtables -F 2>/dev/null", shell=True, capture_output=True)
        except:
            pass
        
        self.logger.info("🛡️  ARP Defense System shutdown complete")
        print(f"{Fore.GREEN}✅ Cleanup complete{Style.RESET_ALL}")

def check_root_permissions():
    """Check if running with sufficient permissions"""
    import os
    if os.geteuid() != 0:
        return False
    return True

def main():
    """Main function"""
    print(f"{Fore.GREEN}{'='*70}")
    print(f"🛡️  ARP DEFENSE SYSTEM")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Comprehensive protection against ARP poisoning attacks{Style.RESET_ALL}")
    
    # Check permissions
    if not check_root_permissions():
        print(f"\n{Fore.RED}❌ PERMISSION ERROR{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This script requires root privileges for:{Style.RESET_ALL}")
        print(f"   • Raw packet capture (ARP monitoring)")
        print(f"   • Sending ARP packets (defense responses)")
        print(f"   • Modifying ARP tables (static entries)")
        print(f"   • Setting iptables/ebtables rules (blocking)")
        print(f"\n{Fore.GREEN}💡 Solution: Run with sudo{Style.RESET_ALL}")
        print(f"   sudo python3 arp_defense_system.py")
        print(f"\n{Fore.CYAN}Or run the automated setup:{Style.RESET_ALL}")
        print(f"   sudo ./run_defense.sh")
        return
    
    print(f"{Fore.GREEN}✅ Running with root privileges{Style.RESET_ALL}")
    
    # Initialize defense system
    try:
        defense = ARPDefenseSystem()
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to initialize defense system: {e}{Style.RESET_ALL}")
        return
    
    def signal_handler(signum, frame):
        defense.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Setup phase
    print(f"\n{Fore.CYAN}🔧 SETUP PHASE{Style.RESET_ALL}")
    
    # Discover network devices
    defense.discover_network_devices()
    
    # Set static ARP entries for critical devices
    defense.set_static_arp_entries()
    
    # Defense phase
    print(f"\n{Fore.GREEN}🛡️  DEFENSE PHASE STARTING{Style.RESET_ALL}")
    
    # Start monitoring and active defense
    defense.start_monitoring()
    defense.start_active_defense()
    
    print(f"{Fore.GREEN}✅ ARP Defense System is now active!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}💡 Press 's' + Enter to show status, 'q' + Enter to quit{Style.RESET_ALL}")
    
    # Status loop
    def status_loop():
        while defense.monitoring_active:
            time.sleep(60)  # Print status every minute
            if defense.stats['attacks_detected'] > 0:
                print(f"\n{Fore.YELLOW}⚡ {defense.stats['attacks_detected']} attacks detected so far...{Style.RESET_ALL}")
    
    status_thread = threading.Thread(target=status_loop, daemon=True)
    status_thread.start()
    
    # Interactive loop
    try:
        while True:
            user_input = input().strip().lower()
            if user_input == 'q':
                break
            elif user_input == 's':
                defense.print_status()
            elif user_input == 'h':
                print(f"\n{Fore.CYAN}Commands:{Style.RESET_ALL}")
                print("  s - Show status")
                print("  q - Quit")
                print("  h - Help")
    
    except KeyboardInterrupt:
        pass
    
    defense.cleanup()

if __name__ == "__main__":
    main() 