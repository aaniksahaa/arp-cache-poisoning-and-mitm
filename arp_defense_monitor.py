#!/usr/bin/env python3
"""
ARP Defense Monitor - Real-time ARP cache poisoning detection and mitigation
Monitors ARP table for suspicious changes and implements countermeasures
"""

import subprocess
import json
import time
import threading
import socket
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from scapy.all import *

# Import centralized configuration
from config import NetworkConfig, DefenseConfig, PathConfig, SecurityConfig

# Use configuration values
INTERFACE = NetworkConfig.INTERFACE
ALERT_THRESHOLD = DefenseConfig.ALERT_THRESHOLD
TIME_WINDOW = DefenseConfig.TIME_WINDOW
MONITOR_INTERVAL = DefenseConfig.ARP_MONITOR_INTERVAL
ENABLE_COUNTERMEASURES = DefenseConfig.ENABLE_COUNTERMEASURES
ENABLE_STATIC_ARP = DefenseConfig.ENABLE_STATIC_ARP
LOG_FILE = PathConfig.ARP_DEFENSE_LOG
VALIDATION_THRESHOLD = DefenseConfig.VALIDATION_THRESHOLD

class ARPDefenseMonitor:
    def __init__(self, interface=None):
        self.interface = interface or INTERFACE
        self.arp_table = {}
        self.trusted_devices = {}
        self.suspicious_events = deque()
        self.alert_counts = defaultdict(int)
        self.running = False
        self.static_entries = {}
        
        # Configuration from centralized config
        self.alert_threshold = ALERT_THRESHOLD
        self.time_window = TIME_WINDOW
        self.monitor_interval = MONITOR_INTERVAL
        self.enable_countermeasures = ENABLE_COUNTERMEASURES
        self.enable_static_arp = ENABLE_STATIC_ARP
        
        # Setup logging
        self.setup_logging()
        
        print(f"🛡️  ARP Defense Monitor initialized")
        print(f"   Interface: {self.interface}")
        print(f"   Alert threshold: {self.alert_threshold}")
        print(f"   Countermeasures: {'Enabled' if self.enable_countermeasures else 'Disabled'}")
        print(f"   Static ARP: {'Enabled' if self.enable_static_arp else 'Disabled'}")
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            filename=LOG_FILE,
            level=getattr(logging, DefenseConfig.LOG_LEVEL),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Also log to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def load_config(self):
        """Load configuration from file or create default"""
        default_config = {
            "alert_threshold": 3,
            "time_window": 60,
            "trusted_devices": {},
            "enable_countermeasures": True,
            "enable_static_arp": True,
            "log_level": "INFO",
            "notification_email": None
        }
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config=None):
        """Save current configuration to file"""
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
        except Exception as e:
            self.logger.error(f"Failed to get gateway IP: {e}")
        return None
    
    def get_current_arp_table(self):
        """Get current system ARP table"""
        arp_table = {}
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '(' in line and ')' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1][1:-1]  # Remove parentheses
                        mac = parts[3]
                        if mac != '<incomplete>':
                            arp_table[ip] = mac
        except Exception as e:
            self.logger.error(f"Failed to get ARP table: {e}")
        return arp_table
    
    def learn_trusted_devices(self):
        """Learn current network devices as trusted (baseline)"""
        self.logger.info("Learning trusted devices from current network state...")
        current_arp = self.get_current_arp_table()
        
        for ip, mac in current_arp.items():
            self.trusted_devices[ip] = mac
            self.logger.info(f"Added trusted device: {ip} -> {mac}")
        
        # Get gateway MAC specifically
        if self.gateway_ip and self.gateway_ip in current_arp:
            self.gateway_mac = current_arp[self.gateway_ip]
            self.logger.info(f"Gateway identified: {self.gateway_ip} -> {self.gateway_mac}")
        
        self.config['trusted_devices'] = self.trusted_devices
        self.save_config()
    
    def detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attempts"""
        if not packet.haslayer(ARP):
            return False
        
        arp = packet[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        op = arp.op  # 1 = request, 2 = reply
        
        current_time = datetime.now()
        
        # Store ARP information
        if src_ip in self.arp_table:
            old_mac, old_time, old_source = self.arp_table[src_ip]
            
            # Check for MAC address changes
            if old_mac != src_mac:
                time_diff = (current_time - old_time).total_seconds()
                
                # Rapid MAC changes are suspicious
                if time_diff < 60:  # Less than 1 minute
                    self.suspicious_activity[src_ip] += 1
                    self.logger.warning(
                        f"MAC change detected for {src_ip}: {old_mac} -> {src_mac} "
                        f"(time diff: {time_diff:.1f}s)"
                    )
                    
                    # Add to history
                    self.mac_history[src_ip].append((src_mac, current_time))
                    if len(self.mac_history[src_ip]) > 10:
                        self.mac_history[src_ip].popleft()
                    
                    return True
        
        # Update ARP table
        self.arp_table[src_ip] = (src_mac, current_time, "packet")
        
        # Check for duplicate MAC addresses
        self.duplicate_detection[src_mac].append(src_ip)
        # Clean old entries
        self.duplicate_detection[src_mac] = [
            ip for ip in self.duplicate_detection[src_mac] 
            if (current_time - self.arp_table.get(ip, (None, current_time - timedelta(hours=1), None))[1]).total_seconds() < 300
        ]
        
        # Alert if one MAC claims multiple IPs
        if len(set(self.duplicate_detection[src_mac])) > 1:
            self.logger.warning(
                f"Duplicate MAC detected: {src_mac} claims IPs {self.duplicate_detection[src_mac]}"
            )
            return True
        
        # Check against trusted devices
        if src_ip in self.trusted_devices:
            trusted_mac = self.trusted_devices[src_ip]
            if src_mac != trusted_mac:
                self.logger.critical(
                    f"TRUSTED DEVICE SPOOFED: {src_ip} has MAC {src_mac} "
                    f"but should be {trusted_mac}"
                )
                return True
        
        return False
    
    def send_counter_arp(self, spoofed_ip, correct_mac):
        """Send counter ARP to restore correct mapping"""
        if not self.config.get('enable_countermeasures', True):
            return
        
        try:
            # Broadcast correct ARP reply
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,  # ARP reply
                psrc=spoofed_ip,
                hwsrc=correct_mac,
                pdst="0.0.0.0",
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            sendp(pkt, iface=self.interface, verbose=0)
            
            self.logger.info(f"Sent counter-ARP for {spoofed_ip} -> {correct_mac}")
            
        except Exception as e:
            self.logger.error(f"Failed to send counter-ARP: {e}")
    
    def set_static_arp_entries(self):
        """Set static ARP entries for trusted devices"""
        if not self.config.get('enable_static_arp', True):
            return
        
        self.logger.info("Setting static ARP entries for trusted devices...")
        
        for ip, mac in self.trusted_devices.items():
            try:
                # Add static ARP entry
                subprocess.run(['sudo', 'arp', '-s', ip, mac], 
                             capture_output=True, check=True)
                self.logger.info(f"Set static ARP: {ip} -> {mac}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to set static ARP for {ip}: {e}")
    
    def remove_static_arp_entries(self):
        """Remove static ARP entries"""
        self.logger.info("Removing static ARP entries...")
        
        for ip in self.trusted_devices:
            try:
                subprocess.run(['sudo', 'arp', '-d', ip], 
                             capture_output=True)
                self.logger.info(f"Removed static ARP: {ip}")
            except subprocess.CalledProcessError:
                pass  # Entry might not exist
    
    def alert_handler(self, alert_type, details):
        """Handle security alerts"""
        alert_msg = f"SECURITY ALERT [{alert_type}]: {details}"
        self.logger.critical(alert_msg)
        
        # Visual alert
        print(f"\n{'='*60}")
        print(f"🚨 {alert_msg}")
        print(f"{'='*60}\n")
        
        # Email notification (if configured)
        if self.config.get('notification_email'):
            self.send_email_alert(alert_type, details)
        
        # Desktop notification (if available)
        try:
            subprocess.run(['notify-send', 'ARP Defense Alert', alert_msg])
        except:
            pass
    
    def send_email_alert(self, alert_type, details):
        """Send email alert (placeholder - implement based on your needs)"""
        # This would integrate with your email system
        self.logger.info(f"Email alert would be sent: {alert_type} - {details}")
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            if self.detect_arp_spoofing(packet):
                arp = packet[ARP]
                src_ip = arp.psrc
                src_mac = arp.hwsrc
                
                # Check if this is a known trusted device being spoofed
                if src_ip in self.trusted_devices:
                    correct_mac = self.trusted_devices[src_ip]
                    self.alert_handler(
                        "ARP SPOOFING", 
                        f"Device {src_ip} spoofed (fake MAC: {src_mac}, real: {correct_mac})"
                    )
                    
                    # Send counter-ARP
                    self.send_counter_arp(src_ip, correct_mac)
                
                # Check if gateway is being spoofed
                elif src_ip == self.gateway_ip and self.gateway_mac:
                    if src_mac != self.gateway_mac:
                        self.alert_handler(
                            "GATEWAY SPOOFING",
                            f"Gateway {src_ip} spoofed (fake MAC: {src_mac}, real: {self.gateway_mac})"
                        )
                        self.send_counter_arp(src_ip, self.gateway_mac)
                
                else:
                    self.alert_handler(
                        "SUSPICIOUS ARP",
                        f"Suspicious ARP activity from {src_ip} ({src_mac})"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in packet handler: {e}")
    
    def monitor_arp_table(self):
        """Continuously monitor system ARP table for changes"""
        last_arp_table = {}
        
        while self.running:
            try:
                current_arp = self.get_current_arp_table()
                
                # Check for changes
                for ip, mac in current_arp.items():
                    if ip in last_arp_table and last_arp_table[ip] != mac:
                        if ip in self.trusted_devices and self.trusted_devices[ip] != mac:
                            self.alert_handler(
                                "ARP TABLE POISONING",
                                f"System ARP table modified: {ip} changed from "
                                f"{last_arp_table[ip]} to {mac}"
                            )
                
                last_arp_table = current_arp
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring ARP table: {e}")
                time.sleep(10)
    
    def start_monitoring(self):
        """Start the defense monitoring system"""
        self.logger.info("Starting ARP Defense Monitor...")
        self.running = True
        
        # Learn current network state if no trusted devices
        if not self.trusted_devices:
            self.learn_trusted_devices()
        
        # Set static ARP entries
        self.set_static_arp_entries()
        
        # Start ARP table monitoring thread
        arp_monitor_thread = threading.Thread(target=self.monitor_arp_table)
        arp_monitor_thread.daemon = True
        arp_monitor_thread.start()
        
        try:
            # Start packet capture
            self.logger.info(f"Starting packet capture on interface {self.interface}")
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.logger.info("Stopping ARP Defense Monitor...")
        self.running = False
        
        # Remove static ARP entries
        if self.config.get('enable_static_arp', True):
            self.remove_static_arp_entries()
        
        self.logger.info("ARP Defense Monitor stopped")
    
    def status_report(self):
        """Generate status report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "trusted_devices": len(self.trusted_devices),
            "monitored_interface": self.interface,
            "gateway": f"{self.gateway_ip} -> {self.gateway_mac}",
            "suspicious_activity_count": sum(self.suspicious_activity.values()),
            "recent_alerts": len([ip for ip, count in self.suspicious_activity.items() if count > 0])
        }
        
        return report

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="ARP Defense Monitor")
    parser.add_argument("-i", "--interface", default="wlo1", 
                       help="Network interface to monitor")
    parser.add_argument("-c", "--config", default="arp_defense_config.json",
                       help="Configuration file path")
    parser.add_argument("--learn", action="store_true",
                       help="Learn current network devices as trusted")
    parser.add_argument("--status", action="store_true",
                       help="Show status report")
    
    args = parser.parse_args()
    
    monitor = ARPDefenseMonitor(args.interface)
    
    if args.learn:
        monitor.learn_trusted_devices()
        print("Trusted devices learned and saved to configuration")
        return
    
    if args.status:
        report = monitor.status_report()
        print(json.dumps(report, indent=2))
        return
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\nShutdown requested...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main() 