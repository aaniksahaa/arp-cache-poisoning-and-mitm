#!/usr/bin/env python3
"""
DNS Interception Test Script
Tests the DNS interception capabilities by making DNS queries
"""

import subprocess
import socket
import time
from scapy.all import *

def test_dns_query(domain):
    """Test DNS query for a specific domain"""
    print(f"🔍 Testing DNS query for: {domain}")
    
    try:
        # Method 1: Using socket.gethostbyname
        start_time = time.time()
        ip = socket.gethostbyname(domain)
        end_time = time.time()
        print(f"   Socket result: {domain} -> {ip} (took {end_time - start_time:.3f}s)")
        
        # Method 2: Using nslookup command
        try:
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True, timeout=5)
            print(f"   nslookup output: {result.stdout.split()[-1] if result.stdout else 'No output'}")
        except:
            print("   nslookup failed")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    print()

def test_with_scapy(domain):
    """Test DNS query using Scapy"""
    print(f"🔍 Testing Scapy DNS query for: {domain}")
    
    try:
        # Create DNS query packet
        dns_query = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        
        # Send query and wait for response
        response = sr1(dns_query, timeout=5, verbose=0)
        
        if response and response.haslayer(DNS):
            dns_resp = response[DNS]
            if dns_resp.ancount > 0:
                for i in range(dns_resp.ancount):
                    answer = dns_resp.an if dns_resp.ancount == 1 else dns_resp.an[i]
                    if answer.type == 1:  # A record
                        print(f"   Scapy result: {domain} -> {answer.rdata}")
            else:
                print(f"   Scapy result: No A records found")
        else:
            print(f"   Scapy result: No response received")
            
    except Exception as e:
        print(f"   Scapy error: {e}")
    
    print()

def main():
    """Main test function"""
    print("=" * 60)
    print("🧪 DNS INTERCEPTION TEST SCRIPT")
    print("=" * 60)
    print("This script tests if DNS queries are being intercepted and modified")
    print("Run this while the DNS interceptor is running to see the effects")
    print("=" * 60)
    
    # Test domains that should be redirected
    test_domains = [
        "youtube.com",
        "m.youtube.com", 
        "www.youtube.com",
        "facebook.com",
        "www.facebook.com",
        "instagram.com",
        "twitter.com",
        "example.com",
        "test.com",
        "google.com",  # This might get modified responses
        "yahoo.com"    # This should not be modified
    ]
    
    print("\n📡 Testing DNS resolution for various domains...")
    print("If DNS interception is working, you should see modified responses")
    print("Check the dns_attack.log file for detailed interception logs\n")
    
    for domain in test_domains:
        test_dns_query(domain)
        time.sleep(1)  # Small delay between queries
    
    print("\n🔬 Testing with Scapy (direct DNS queries)...")
    print("These queries bypass system DNS cache\n")
    
    for domain in ["youtube.com", "facebook.com", "example.com"]:
        test_with_scapy(domain)
        time.sleep(1)
    
    print("=" * 60)
    print("🏁 DNS interception test completed!")
    print("Check the following to verify interception:")
    print("1. dns_attack.log - Should show intercepted queries/responses")
    print("2. Modified IP addresses in the results above")
    print("3. Domain redirections (e.g., youtube.com -> google.com)")
    print("=" * 60)

if __name__ == "__main__":
    main()
