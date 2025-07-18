#!/usr/bin/env python3
"""
Attack Configuration Display Tool
Shows current attack settings, target information, and network status
"""

import subprocess
import sys
from config import NetworkConfig, AttackConfig, DefenseConfig, SecurityConfig

def check_network_connectivity(ip):
    """Check if a target IP is reachable"""
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                              capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def get_arp_info(ip):
    """Get MAC address from ARP table"""
    try:
        result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
        if result.returncode == 0 and ip in result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if ip in line and 'incomplete' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]  # MAC address
    except:
        pass
    return None

def get_interface_info(interface):
    """Get interface status and IP"""
    try:
        result = subprocess.run(['ip', 'addr', 'show', interface], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            status = "UP" if "state UP" in result.stdout else "DOWN"
            ip = None
            for line in lines:
                if 'inet ' in line and 'scope global' in line:
                    ip = line.split()[1].split('/')[0]
                    break
            return status, ip
    except:
        pass
    return "UNKNOWN", None

def show_attack_configuration():
    """Display comprehensive attack configuration"""
    print("=" * 80)
    print("🎯 ARP CACHE POISONING & MITM ATTACK - CONFIGURATION STATUS")
    print("=" * 80)
    
    # Network Interface Information
    print(f"\n📡 NETWORK INTERFACE:")
    interface_status, local_ip = get_interface_info(NetworkConfig.INTERFACE)
    print(f"   Interface: {NetworkConfig.INTERFACE}")
    print(f"   Status: {interface_status}")
    print(f"   Local IP: {local_ip or 'Not assigned'}")
    print(f"   Network Range: {NetworkConfig.NETWORK_RANGE}")
    
    # Attack Targets
    print(f"\n🎯 ATTACK TARGETS:")
    
    # Victim Information
    victim_reachable = check_network_connectivity(AttackConfig.VICTIM_IP)
    victim_arp_mac = get_arp_info(AttackConfig.VICTIM_IP)
    
    print(f"   👤 Victim Device:")
    print(f"      IP Address: {AttackConfig.VICTIM_IP}")
    print(f"      Configured MAC: {AttackConfig.VICTIM_MAC}")
    print(f"      Status: {'🟢 Reachable' if victim_reachable else '🔴 Unreachable'}")
    
    if victim_arp_mac:
        mac_match = victim_arp_mac.lower() == AttackConfig.VICTIM_MAC.lower()
        print(f"      ARP Table MAC: {victim_arp_mac} {'✅' if mac_match else '❌ MISMATCH'}")
    else:
        print(f"      ARP Table MAC: ❌ Not found")
    
    # Gateway Information
    gateway_reachable = check_network_connectivity(AttackConfig.GATEWAY_IP)
    gateway_arp_mac = get_arp_info(AttackConfig.GATEWAY_IP)
    
    print(f"\n   🌐 Gateway/Router:")
    print(f"      IP Address: {AttackConfig.GATEWAY_IP}")
    print(f"      Configured MAC: {AttackConfig.GATEWAY_MAC}")
    print(f"      Status: {'🟢 Reachable' if gateway_reachable else '🔴 Unreachable'}")
    
    if gateway_arp_mac:
        mac_match = gateway_arp_mac.lower() == AttackConfig.GATEWAY_MAC.lower()
        print(f"      ARP Table MAC: {gateway_arp_mac} {'✅' if mac_match else '❌ MISMATCH'}")
    else:
        print(f"      ARP Table MAC: ❌ Not found")
    
    # HTTP Injection Configuration
    print(f"\n💉 HTTP INJECTION SETTINGS:")
    current_payload = AttackConfig.INJECTION_PAYLOADS.get(
        AttackConfig.CURRENT_PAYLOAD, AttackConfig.INJECTION_CODE
    )
    
    # Get payload preview
    if isinstance(current_payload, bytes):
        payload_preview = current_payload.decode('utf-8', errors='ignore')[:80]
    else:
        payload_preview = str(current_payload)[:80]
    
    print(f"   Injection Enabled: {'✅' if AttackConfig.ENABLE_HTTP_INJECTION else '❌'}")
    print(f"   Current Payload: {AttackConfig.CURRENT_PAYLOAD}")
    print(f"   Payload Preview: {payload_preview}{'...' if len(payload_preview) >= 80 else ''}")
    print(f"   Packet Logging: {'✅' if AttackConfig.ENABLE_PACKET_LOGGING else '❌'}")
    print(f"   Gzip Support: {'✅' if AttackConfig.ENABLE_GZIP_HANDLING else '❌'}")
    
    # Attack Parameters
    print(f"\n⚙️  ATTACK PARAMETERS:")
    print(f"   ARP Poison Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
    print(f"   Available Payloads: {list(AttackConfig.INJECTION_PAYLOADS.keys())}")
    
    # Security & Safety Settings
    print(f"\n🛡️  SECURITY SETTINGS:")
    print(f"   Require Confirmation: {'✅' if SecurityConfig.REQUIRE_CONFIRMATION else '❌'}")
    print(f"   Auto Cleanup: {'✅' if SecurityConfig.AUTO_CLEANUP else '❌'}")
    print(f"   Show Legal Warning: {'✅' if SecurityConfig.SHOW_LEGAL_WARNING else '❌'}")
    print(f"   Max Attack Duration: {SecurityConfig.MAX_ATTACK_DURATION} seconds")
    print(f"   Activity Logging: {'✅' if SecurityConfig.LOG_ACTIVITIES else '❌'}")
    
    # Defense Configuration (for reference)
    print(f"\n🔒 DEFENSE SETTINGS (Reference):")
    print(f"   Countermeasures: {'✅' if DefenseConfig.ENABLE_COUNTERMEASURES else '❌'}")
    print(f"   Static ARP: {'✅' if DefenseConfig.ENABLE_STATIC_ARP else '❌'}")
    print(f"   Alert Threshold: {DefenseConfig.ALERT_THRESHOLD}")
    print(f"   Monitor Interval: {DefenseConfig.ARP_MONITOR_INTERVAL}s")
    
    # System Status Checks
    print(f"\n🔧 SYSTEM STATUS:")
    
    # Check if running as root
    import os
    is_root = os.geteuid() == 0
    print(f"   Root Privileges: {'✅' if is_root else '❌ Required for packet manipulation'}")
    
    # Check required tools
    tools_status = {}
    required_tools = ['iptables', 'arp', 'ping']
    for tool in required_tools:
        try:
            result = subprocess.run(['which', tool], capture_output=True)
            tools_status[tool] = result.returncode == 0
        except:
            tools_status[tool] = False
    
    print(f"   Required Tools:")
    for tool, available in tools_status.items():
        print(f"      {tool}: {'✅' if available else '❌'}")
    
    # Check Python modules
    modules_status = {}
    required_modules = ['scapy', 'netfilterqueue']
    for module in required_modules:
        try:
            __import__(module)
            modules_status[module] = True
        except ImportError:
            modules_status[module] = False
    
    print(f"   Python Modules:")
    for module, available in modules_status.items():
        print(f"      {module}: {'✅' if available else '❌'}")
    
    # IP Forwarding status
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            ip_forward = f.read().strip() == '1'
        print(f"   IP Forwarding: {'✅ Enabled' if ip_forward else '❌ Disabled'}")
    except:
        print(f"   IP Forwarding: ❓ Unable to check")
    
    print(f"\n📝 CONFIGURATION FILES:")
    import os
    config_files = [
        ('config.py', 'Main configuration'),
        ('user_config.py', 'User customization'),
        ('user_config_template.py', 'Configuration template')
    ]
    
    for filename, description in config_files:
        exists = os.path.exists(filename)
        print(f"   {filename}: {'✅' if exists else '❌'} ({description})")
    
    print("=" * 80)
    
    # Summary and Recommendations
    print(f"\n📊 READINESS ASSESSMENT:")
    
    issues = []
    if not victim_reachable:
        issues.append("Victim device unreachable")
    if not gateway_reachable:
        issues.append("Gateway unreachable")
    if victim_arp_mac and victim_arp_mac.lower() != AttackConfig.VICTIM_MAC.lower():
        issues.append("Victim MAC address mismatch")
    if gateway_arp_mac and gateway_arp_mac.lower() != AttackConfig.GATEWAY_MAC.lower():
        issues.append("Gateway MAC address mismatch")
    if not is_root:
        issues.append("Root privileges required")
    if not all(tools_status.values()):
        issues.append("Missing required system tools")
    if not all(modules_status.values()):
        issues.append("Missing required Python modules")
    
    if not issues:
        print("   🟢 READY FOR ATTACK - All systems check passed")
        print("   ▶️  Run: sudo python3 arp_mitm_attack.py")
    else:
        print("   🔴 ISSUES DETECTED:")
        for issue in issues:
            print(f"      ❌ {issue}")
        print("   🔧 Fix issues before proceeding with attack")
    
    print("=" * 80)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Show ARP MITM Attack Configuration")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    args = parser.parse_args()
    
    if args.json:
        # JSON output for programmatic use
        import json
        config_data = {
            "network": {
                "interface": NetworkConfig.INTERFACE,
                "network_range": NetworkConfig.NETWORK_RANGE
            },
            "targets": {
                "victim_ip": AttackConfig.VICTIM_IP,
                "victim_mac": AttackConfig.VICTIM_MAC,
                "gateway_ip": AttackConfig.GATEWAY_IP,
                "gateway_mac": AttackConfig.GATEWAY_MAC
            },
            "attack": {
                "injection_enabled": AttackConfig.ENABLE_HTTP_INJECTION,
                "current_payload": AttackConfig.CURRENT_PAYLOAD,
                "poison_interval": AttackConfig.ARP_POISON_INTERVAL
            },
            "security": {
                "require_confirmation": SecurityConfig.REQUIRE_CONFIRMATION,
                "auto_cleanup": SecurityConfig.AUTO_CLEANUP,
                "max_duration": SecurityConfig.MAX_ATTACK_DURATION
            }
        }
        print(json.dumps(config_data, indent=2))
    else:
        # Human-readable output
        show_attack_configuration()

if __name__ == "__main__":
    main() 