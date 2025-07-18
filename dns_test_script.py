#!/usr/bin/env python3
"""
DNS Test Script - Simple DNS packet analysis and modification demo
This script helps understand DNS packets and test basic DNS manipulation
"""

from scapy.all import *
import sys
import time

def analyze_dns_packet(packet):
    """Analyze and display DNS packet information"""
    if packet.haslayer(DNS):
        dns = packet[DNS]
        print(f"\n{'='*50}")
        print(f"DNS Packet Analysis")
        print(f"{'='*50}")
        print(f"Transaction ID: {dns.id}")
        print(f"Query/Response: {'Response' if dns.qr else 'Query'}")
        print(f"Opcode: {dns.opcode}")
        print(f"Response Code: {dns.rcode}")
        
        # Analyze questions (queries)
        if dns.qdcount > 0:
            print(f"\nDNS Questions ({dns.qdcount}):")
            for i in range(dns.qdcount):
                if i == 0:
                    qname = dns.qd.qname if hasattr(dns.qd, 'qname') else dns[DNSQR].qname
                    qtype = dns.qd.qtype if hasattr(dns.qd, 'qtype') else dns[DNSQR].qtype
                    print(f"  Query: {qname.decode('utf-8').rstrip('.')} (Type: {qtype})")
        
        # Analyze answers (responses)
        if dns.ancount > 0:
            print(f"\nDNS Answers ({dns.ancount}):")
            for i in range(dns.ancount):
                if hasattr(dns, 'an'):
                    if isinstance(dns.an, list):
                        answer = dns.an[i]
                    else:
                        answer = dns.an
                    
                    if answer.type == 1:  # A record
                        domain = answer.rrname.decode('utf-8').rstrip('.')
                        ip = answer.rdata
                        print(f"  {domain} -> {ip} (TTL: {answer.ttl})")
                    elif answer.type == 5:  # CNAME record
                        domain = answer.rrname.decode('utf-8').rstrip('.')
                        cname = answer.rdata.decode('utf-8').rstrip('.')
                        print(f"  {domain} -> {cname} (CNAME, TTL: {answer.ttl})")

def create_fake_dns_response(query_packet, fake_ip):
    """Create a fake DNS response with a custom IP"""
    if not query_packet.haslayer(DNS) or not query_packet.haslayer(DNSQR):
        return None
    
    # Extract query information
    original_dns = query_packet[DNS]
    original_query = query_packet[DNSQR]
    original_domain = original_query.qname
    
    # Create fake response
    fake_response = IP(dst=query_packet[IP].src, src=query_packet[IP].dst) / \
                   UDP(dport=query_packet[UDP].sport, sport=query_packet[UDP].dport) / \
                   DNS(id=original_dns.id,
                       qr=1,  # Response
                       aa=1,  # Authoritative answer
                       qd=original_query,
                       an=DNSRR(rrname=original_domain,
                               type=1,  # A record
                               rdata=fake_ip,
                               ttl=300))
    
    return fake_response

def monitor_dns_traffic():
    """Monitor DNS traffic on the network"""
    print("🔍 Monitoring DNS traffic...")
    print("Press Ctrl+C to stop")
    
    def packet_handler(packet):
        if packet.haslayer(DNS):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            dns = packet[DNS]
            if dns.qr == 0:  # DNS Query
                if packet.haslayer(DNSQR):
                    domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                    print(f"📤 DNS Query: {src_ip} -> {dst_ip} | Domain: {domain}")
            
            elif dns.qr == 1:  # DNS Response
                print(f"📥 DNS Response: {src_ip} -> {dst_ip}")
                if dns.ancount > 0:
                    # Try to extract the answer
                    try:
                        answer = dns.an
                        if answer.type == 1:  # A record
                            domain = answer.rrname.decode('utf-8').rstrip('.')
                            ip = answer.rdata
                            print(f"   📍 {domain} -> {ip}")
                    except:
                        print(f"   📍 (Could not parse answer)")
    
    try:
        sniff(filter="udp port 53", prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopping DNS monitoring")

def test_dns_query(domain):
    """Send a test DNS query and analyze the response"""
    print(f"🔍 Testing DNS query for: {domain}")
    
    # Create DNS query
    query = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    
    print(f"📤 Sending DNS query...")
    analyze_dns_packet(query)
    
    # Send query and wait for response
    response = sr1(query, timeout=5, verbose=False)
    
    if response:
        print(f"\n📥 Received DNS response:")
        analyze_dns_packet(response)
        
        # Demonstrate creating a fake response
        fake_ip = "192.168.1.100"
        fake_response = create_fake_dns_response(query, fake_ip)
        
        print(f"\n🎭 Example of fake DNS response (IP changed to {fake_ip}):")
        analyze_dns_packet(fake_response)
    else:
        print("❌ No response received")

def demonstrate_dns_spoofing():
    """Demonstrate DNS spoofing concept"""
    print("\n" + "="*60)
    print("🎭 DNS SPOOFING DEMONSTRATION")
    print("="*60)
    
    # Example domains
    test_domains = ['google.com', 'youtube.com', 'github.com']
    
    for domain in test_domains:
        print(f"\n🔍 Testing DNS spoofing for: {domain}")
        
        # Create legitimate query
        query = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        
        # Get real response
        print("📤 Getting real DNS response...")
        real_response = sr1(query, timeout=3, verbose=False)
        
        if real_response and real_response.haslayer(DNS) and real_response[DNS].ancount > 0:
            real_ip = real_response[DNS].an.rdata
            print(f"✅ Real IP for {domain}: {real_ip}")
            
            # Create fake response
            fake_ip = "192.168.1.100"
            fake_response = create_fake_dns_response(query, fake_ip)
            
            print(f"🎭 Fake IP for {domain}: {fake_ip}")
            print(f"💥 DNS spoofing would redirect {domain} to your attack server!")
        else:
            print(f"❌ Could not get real response for {domain}")

def main():
    """Main menu"""
    if len(sys.argv) < 2:
        print("🧪 DNS Test Script")
        print("="*40)
        print("Usage:")
        print(f"  {sys.argv[0]} monitor         - Monitor DNS traffic")
        print(f"  {sys.argv[0]} query <domain>  - Test DNS query")
        print(f"  {sys.argv[0]} demo            - DNS spoofing demo")
        print("\nExamples:")
        print(f"  {sys.argv[0]} monitor")
        print(f"  {sys.argv[0]} query google.com")
        print(f"  {sys.argv[0]} demo")
        return
    
    action = sys.argv[1].lower()
    
    if action == "monitor":
        monitor_dns_traffic()
    
    elif action == "query":
        if len(sys.argv) < 3:
            print("❌ Please specify a domain to query")
            print(f"Example: {sys.argv[0]} query google.com")
            return
        
        domain = sys.argv[2]
        test_dns_query(domain)
    
    elif action == "demo":
        demonstrate_dns_spoofing()
    
    else:
        print(f"❌ Unknown action: {action}")
        print("Use 'monitor', 'query', or 'demo'")

if __name__ == "__main__":
    main() 