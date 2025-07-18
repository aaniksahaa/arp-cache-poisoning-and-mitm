#!/usr/bin/env python3
"""
MITM Diagnosis Tool
Checks if ARP poisoning is working and traffic is being routed correctly
"""

import subprocess
import time
from config import NetworkConfig, AttackConfig

def get_arp_table():
    """Get current ARP table"""
    arp_entries = {}
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if '(' in line and ')' in line and 'ether' in line:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[1][1:-1]  # Remove parentheses
                    mac = parts[3]
                    arp_entries[ip] = mac
    except:
        pass
    return arp_entries

def get_attacker_mac():
    """Get attacker's MAC address"""
    try:
        result = subprocess.run(['cat', f'/sys/class/net/{NetworkConfig.INTERFACE}/address'], 
                              capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return None

def check_routing_table():
    """Check routing table"""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        return result.stdout
    except:
        return "Could not get routing table"

def check_ip_forwarding():
    """Check if IP forwarding is enabled"""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            return f.read().strip() == '1'
    except:
        return False

def ping_test(target_ip):
    """Test connectivity to target"""
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '2', target_ip], 
                              capture_output=True)
        return result.returncode == 0
    except:
        return False

def check_iptables_rules():
    """Check current iptables rules"""
    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
        return result.stdout
    except:
        return "Could not get iptables rules"

def traceroute_test(target_ip):
    """Test routing path to target"""
    try:
        result = subprocess.run(['traceroute', '-n', '-m', '3', target_ip], 
                              capture_output=True, text=True, timeout=10)
        return result.stdout
    except:
        return "Traceroute failed or not available"

def diagnose_mitm():
    """Run comprehensive MITM diagnosis"""
    print("=" * 80)
    print("🔍 MITM ATTACK DIAGNOSIS")
    print("=" * 80)
    
    # Get configuration
    victim_ip = AttackConfig.VICTIM_IP
    gateway_ip = AttackConfig.GATEWAY_IP
    interface = NetworkConfig.INTERFACE
    
    print(f"\n📋 CONFIGURATION:")
    print(f"   Victim IP: {victim_ip}")
    print(f"   Gateway IP: {gateway_ip}")
    print(f"   Interface: {interface}")
    
    # Get attacker MAC
    attacker_mac = get_attacker_mac()
    print(f"   Attacker MAC: {attacker_mac}")
    
    # Check basic connectivity
    print(f"\n🌐 CONNECTIVITY TEST:")
    victim_reachable = ping_test(victim_ip)
    gateway_reachable = ping_test(gateway_ip)
    
    print(f"   Victim ({victim_ip}): {'✅ Reachable' if victim_reachable else '❌ Unreachable'}")
    print(f"   Gateway ({gateway_ip}): {'✅ Reachable' if gateway_reachable else '❌ Unreachable'}")
    
    # Check ARP table
    print(f"\n📋 ARP TABLE ANALYSIS:")
    arp_table = get_arp_table()
    
    victim_arp_mac = arp_table.get(victim_ip)
    gateway_arp_mac = arp_table.get(gateway_ip)
    
    print(f"   Victim ARP entry: {victim_ip} -> {victim_arp_mac or 'Not found'}")
    print(f"   Gateway ARP entry: {gateway_ip} -> {gateway_arp_mac or 'Not found'}")
    
    # Check if ARP poisoning is working
    if victim_arp_mac:
        if victim_arp_mac.lower() == attacker_mac.lower():
            print(f"   🚨 VICTIM POISONED: Victim shows attacker MAC as gateway")
        else:
            print(f"   ❌ Victim NOT poisoned: Shows real gateway MAC")
    
    if gateway_arp_mac:
        if gateway_arp_mac.lower() == attacker_mac.lower():
            print(f"   🚨 GATEWAY POISONED: Gateway shows attacker MAC for victim")
        else:
            print(f"   ❌ Gateway NOT poisoned: Shows real victim MAC")
    
    # Check system configuration
    print(f"\n⚙️ SYSTEM CONFIGURATION:")
    ip_forward = check_ip_forwarding()
    print(f"   IP Forwarding: {'✅ Enabled' if ip_forward else '❌ Disabled'}")
    
    # Check iptables
    print(f"\n🔥 IPTABLES RULES:")
    iptables_output = check_iptables_rules()
    if 'NFQUEUE' in iptables_output:
        print(f"   ✅ NFQUEUE rule found in iptables")
    else:
        print(f"   ❌ No NFQUEUE rule found")
    
    if 'FORWARD' in iptables_output:
        forward_lines = [line for line in iptables_output.split('\n') if 'FORWARD' in line]
        print(f"   FORWARD chain rules: {len(forward_lines)}")
    
    # Routing analysis
    print(f"\n🗺️ ROUTING ANALYSIS:")
    routing_table = check_routing_table()
    default_route = None
    for line in routing_table.split('\n'):
        if 'default' in line:
            default_route = line
            break
    
    if default_route:
        print(f"   Default route: {default_route}")
    else:
        print(f"   ❌ No default route found")
    
    # Traceroute test
    print(f"\n🛤️ TRACEROUTE TO VICTIM:")
    traceroute_output = traceroute_test(victim_ip)
    print(f"   {traceroute_output}")
    
    # Traffic flow analysis
    print(f"\n📊 TRAFFIC FLOW ANALYSIS:")
    print(f"   Expected flow for MITM:")
    print(f"     1. Victim ({victim_ip}) -> Attacker ({attacker_mac})")
    print(f"     2. Attacker forwards to Gateway ({gateway_ip})")
    print(f"     3. Gateway responds to Attacker")
    print(f"     4. Attacker modifies and forwards to Victim")
    
    # Summary and recommendations
    print(f"\n🎯 DIAGNOSIS SUMMARY:")
    issues = []
    
    if not victim_reachable:
        issues.append("Victim unreachable")
    if not gateway_reachable:
        issues.append("Gateway unreachable")
    if not victim_arp_mac or victim_arp_mac.lower() != attacker_mac.lower():
        issues.append("Victim ARP not poisoned")
    if not gateway_arp_mac or gateway_arp_mac.lower() != attacker_mac.lower():
        issues.append("Gateway ARP not poisoned")
    if not ip_forward:
        issues.append("IP forwarding disabled")
    if 'NFQUEUE' not in iptables_output:
        issues.append("iptables NFQUEUE rule missing")
    
    if not issues:
        print(f"   ✅ All checks passed - MITM should be working")
        print(f"   💡 If injection still fails, check:")
        print(f"      - HTTPS vs HTTP traffic")
        print(f"      - Content-Type headers")
        print(f"      - Network application behavior")
    else:
        print(f"   ❌ Issues found:")
        for issue in issues:
            print(f"      • {issue}")
        
        print(f"\n🔧 RECOMMENDED FIXES:")
        if "IP forwarding disabled" in issues:
            print(f"      • Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward")
        if "iptables NFQUEUE rule missing" in issues:
            print(f"      • Add iptables rule: iptables -I FORWARD -j NFQUEUE --queue-num 0")
        if "Victim ARP not poisoned" in issues or "Gateway ARP not poisoned" in issues:
            print(f"      • Check ARP poisoning is running")
            print(f"      • Verify target IPs and MACs are correct")
            print(f"      • Ensure attacker is on same network segment")
    
    print("=" * 80)

def monitor_arp_changes():
    """Monitor ARP table changes in real-time"""
    print("🔍 Monitoring ARP table changes (Press Ctrl+C to stop)...")
    
    previous_arp = get_arp_table()
    attacker_mac = get_attacker_mac()
    
    try:
        while True:
            time.sleep(2)
            current_arp = get_arp_table()
            
            # Check for changes
            for ip, mac in current_arp.items():
                if ip in previous_arp:
                    if previous_arp[ip] != mac:
                        print(f"📝 ARP CHANGE: {ip} changed from {previous_arp[ip]} to {mac}")
                        if mac.lower() == attacker_mac.lower():
                            print(f"   🎯 POISONED: {ip} now points to attacker")
                        else:
                            print(f"   🔄 RESTORED: {ip} restored to legitimate MAC")
                else:
                    print(f"📝 NEW ARP ENTRY: {ip} -> {mac}")
            
            previous_arp = current_arp
            
    except KeyboardInterrupt:
        print("\n👋 Monitoring stopped")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="MITM Attack Diagnosis Tool")
    parser.add_argument("--monitor", action="store_true", help="Monitor ARP changes")
    
    args = parser.parse_args()
    
    if args.monitor:
        monitor_arp_changes()
    else:
        diagnose_mitm()

if __name__ == "__main__":
    main() 