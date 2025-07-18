#!/usr/bin/env python3
"""
TCP Debug Helper - Troubleshoot TCP socket interception issues
Helps identify common problems with bidirectional TCP interception
"""

import subprocess
import socket
import time
import threading
from scapy.all import *

def check_network_connectivity():
    """Basic network connectivity tests"""
    print("🔍 NETWORK CONNECTIVITY TESTS")
    print("=" * 50)
    
    # Get current IP configuration
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        print("📡 Network Interfaces:")
        for line in result.stdout.split('\n'):
            if 'inet ' in line and '127.0.0.1' not in line:
                print(f"   {line.strip()}")
    except:
        print("❌ Could not get network interfaces")
    
    # Check ARP table
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        print("\n🔗 ARP Table:")
        for line in result.stdout.split('\n')[:10]:  # Show first 10 entries
            if line.strip():
                print(f"   {line.strip()}")
    except:
        print("❌ Could not get ARP table")
    
    # Check routing table
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        print("\n🛣️ Routing Table:")
        for line in result.stdout.split('\n')[:5]:  # Show first 5 entries
            if line.strip():
                print(f"   {line.strip()}")
    except:
        print("❌ Could not get routing table")

def test_tcp_connection(server_ip, port=9999):
    """Test basic TCP connection without interception"""
    print(f"\n🔌 TCP CONNECTION TEST")
    print("=" * 50)
    
    try:
        print(f"Testing connection to {server_ip}:{port}...")
        
        # Test connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        start_time = time.time()
        result = sock.connect_ex((server_ip, port))
        end_time = time.time()
        
        if result == 0:
            print(f"✅ Connection successful in {(end_time - start_time)*1000:.1f}ms")
            
            # Test basic send/receive
            test_message = "TCP_DEBUG_TEST"
            sock.send(test_message.encode())
            print(f"📤 Sent: {test_message}")
            
            try:
                response = sock.recv(1024)
                print(f"📥 Received: {response.decode('utf-8', errors='ignore')}")
            except socket.timeout:
                print("⏰ No response received (timeout)")
            
            sock.close()
        else:
            print(f"❌ Connection failed: Error {result}")
            
    except Exception as e:
        print(f"❌ Connection error: {e}")

def monitor_tcp_traffic(target_port=9999, duration=30):
    """Monitor TCP traffic on specified port"""
    print(f"\n📊 TCP TRAFFIC MONITOR (Port {target_port})")
    print("=" * 50)
    
    packets_captured = 0
    
    def packet_handler(packet):
        nonlocal packets_captured
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            tcp_layer = packet[TCP]
            if tcp_layer.dport == target_port or tcp_layer.sport == target_port:
                packets_captured += 1
                payload = packet[Raw].load
                
                print(f"📦 Packet #{packets_captured}:")
                print(f"   {packet[IP].src}:{tcp_layer.sport} → {packet[IP].dst}:{tcp_layer.dport}")
                print(f"   Size: {len(payload)} bytes")
                
                try:
                    decoded = payload.decode('utf-8', errors='ignore')
                    preview = decoded[:100] + "..." if len(decoded) > 100 else decoded
                    print(f"   Content: {repr(preview)}")
                except:
                    print(f"   Content: Binary data")
                print()
    
    print(f"🎯 Monitoring TCP traffic on port {target_port} for {duration} seconds...")
    print("💡 Send some test messages to see captured packets")
    print("🛑 Press Ctrl+C to stop early")
    
    try:
        sniff(filter=f"tcp port {target_port}", prn=packet_handler, timeout=duration)
    except KeyboardInterrupt:
        print("\n⏹️ Monitoring stopped by user")
    
    print(f"\n📊 Summary: Captured {packets_captured} TCP packets")

def check_iptables_rules():
    """Check current iptables rules"""
    print("\n🛡️ IPTABLES RULES CHECK")
    print("=" * 50)
    
    try:
        # Check FORWARD chain
        result = subprocess.run(['sudo', 'iptables', '-L', 'FORWARD', '-n', '-v'], 
                              capture_output=True, text=True)
        print("📋 FORWARD Chain:")
        for line in result.stdout.split('\n'):
            if 'NFQUEUE' in line or 'policy' in line.lower() or 'chain' in line.lower():
                print(f"   {line}")
        
        # Check NAT table
        result = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-L', '-n'], 
                              capture_output=True, text=True)
        print("\n📋 NAT Table:")
        for line in result.stdout.split('\n')[:10]:  # Show first 10 lines
            if line.strip():
                print(f"   {line}")
                
    except Exception as e:
        print(f"❌ Could not check iptables: {e}")

def test_sequence_numbers():
    """Test TCP sequence number handling"""
    print("\n🔢 TCP SEQUENCE NUMBER TEST")
    print("=" * 50)
    
    # This is a simplified test - in practice, sequence numbers are complex
    original_msg = "hello world"
    modified_msg = "Bye world"
    
    print(f"Original message: '{original_msg}' ({len(original_msg)} bytes)")
    print(f"Modified message: '{modified_msg}' ({len(modified_msg)} bytes)")
    print(f"Size difference: {len(modified_msg) - len(original_msg)} bytes")
    
    if len(modified_msg) != len(original_msg):
        print("⚠️ SIZE MISMATCH DETECTED!")
        print("💡 This can cause TCP sequence number issues")
        
        # Show padding solution
        padded_msg = modified_msg + " " * (len(original_msg) - len(modified_msg))
        print(f"Padded message: '{padded_msg}' ({len(padded_msg)} bytes)")
        print("✅ Padding preserves packet size")
    else:
        print("✅ Message sizes match - no sequence number issues expected")

def check_ip_forwarding():
    """Check IP forwarding status"""
    print("\n🔄 IP FORWARDING CHECK")
    print("=" * 50)
    
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            status = f.read().strip()
            if status == '1':
                print("✅ IP forwarding is ENABLED")
            else:
                print("❌ IP forwarding is DISABLED")
                print("💡 Enable with: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
    except:
        print("❌ Could not check IP forwarding status")

def main():
    """Main debugging function"""
    print("🔧 TCP SOCKET INTERCEPTION DEBUG HELPER")
    print("=" * 60)
    
    while True:
        print("\n🛠️ Available Tests:")
        print("1. Network connectivity check")
        print("2. TCP connection test")
        print("3. Monitor TCP traffic")
        print("4. Check iptables rules")
        print("5. TCP sequence number test")
        print("6. Check IP forwarding")
        print("7. Run all tests")
        print("0. Exit")
        
        choice = input("\nSelect test (0-7): ").strip()
        
        if choice == '0':
            print("👋 Goodbye!")
            break
        elif choice == '1':
            check_network_connectivity()
        elif choice == '2':
            server_ip = input("Enter server IP: ").strip()
            if server_ip:
                test_tcp_connection(server_ip)
        elif choice == '3':
            port = input("Enter port to monitor (default 9999): ").strip()
            port = int(port) if port.isdigit() else 9999
            duration = input("Monitor duration in seconds (default 30): ").strip()
            duration = int(duration) if duration.isdigit() else 30
            monitor_tcp_traffic(port, duration)
        elif choice == '4':
            check_iptables_rules()
        elif choice == '5':
            test_sequence_numbers()
        elif choice == '6':
            check_ip_forwarding()
        elif choice == '7':
            check_network_connectivity()
            check_ip_forwarding()
            check_iptables_rules()
            test_sequence_numbers()
            print("\n✅ All basic tests completed")
        else:
            print("❌ Invalid choice, please try again")

if __name__ == "__main__":
    main() 