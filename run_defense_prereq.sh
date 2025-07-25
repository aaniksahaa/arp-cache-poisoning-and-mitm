#!/bin/bash

echo "🛡️  ARP Defense System Setup"
echo "============================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root for full functionality"
   echo ""
   echo "🔧 Root privileges are required for:"
   echo "   • Raw packet capture (ARP monitoring)"
   echo "   • Sending ARP packets (defense responses)"
   echo "   • Modifying ARP tables (static entries)"
   echo "   • Setting firewall rules (attacker blocking)"
   echo ""
   echo "💡 Solution: Run with sudo"
   echo "   sudo ./run_defense.sh"
   exit 1
fi

echo "✅ Running with root privileges"

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
if pip3 install -r requirements_defense.txt; then
    echo "✅ Dependencies installed successfully"
else
    echo "⚠️  Some dependencies may have failed to install"
    echo "💡 Try: apt-get install python3-pip python3-scapy"
fi

# Check if ebtables is available (for MAC blocking)
echo ""
echo "🔧 Checking system tools..."
if ! command -v ebtables &> /dev/null; then
    echo "⚠️  ebtables not found - installing for MAC address blocking..."
    if apt-get update && apt-get install -y ebtables; then
        echo "✅ ebtables installed"
    else
        echo "⚠️  Failed to install ebtables - MAC blocking may not work"
    fi
else
    echo "✅ ebtables found"
fi

# Check if arp command is available
if ! command -v arp &> /dev/null; then
    echo "⚠️  arp command not found - installing net-tools..."
    apt-get install -y net-tools
fi

# Make sure we can modify ARP table and enable forwarding
echo ""
echo "🔧 Setting up system permissions..."
echo 1 > /proc/sys/net/ipv4/ip_forward
if [[ $? -eq 0 ]]; then
    echo "✅ IP forwarding enabled"
else
    echo "⚠️  Could not enable IP forwarding"
fi

# Clean up any existing iptables/ebtables rules
echo ""
echo "🧹 Cleaning up existing rules..."
iptables -F 2>/dev/null
ebtables -F 2>/dev/null
echo "✅ Firewall rules cleaned"

# Test raw socket permissions
echo ""
echo "🔍 Testing raw socket permissions..."
python3 -c "
import socket
try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0806)
    sock.close()
    print('✅ Raw socket permissions OK')
except PermissionError:
    print('❌ Raw socket permission denied')
    print('💡 This might indicate a system restriction')
except Exception as e:
    print(f'⚠️  Raw socket test failed: {e}')
"

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Starting ARP Defense System..."
echo "   The system will provide feedback about available features"
echo "   Press Ctrl+C to stop and view statistics"
echo ""

# Run the defense system
python3 arp_defense_system.py 