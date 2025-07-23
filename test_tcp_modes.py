#!/usr/bin/env python3
"""
Test Script for TCP Attack Modes
Demonstrates MONITOR, TAMPER, and DROP modes
"""

import os
import sys
import time
import subprocess
import signal

# Import the config to modify the TCP attack mode
from config import AttackConfig

def test_mode(mode):
    """Test a specific TCP attack mode"""
    print(f"\n{'='*60}")
    print(f"🧪 TESTING {mode} MODE")
    print(f"{'='*60}")
    
    # Update the config
    AttackConfig.TCP_ATTACK_MODE = mode
    
    # Display what this mode does
    mode_descriptions = {
        "MONITOR": {
            "icon": "👁️",
            "action": "Monitors and logs all TCP messages without modification",
            "expected": "Clean logs showing intercepted messages, packets forwarded normally"
        },
        "TAMPER": {
            "icon": "🔧", 
            "action": "Intercepts and modifies TCP messages based on configured replacements",
            "expected": "Messages modified according to SOCKET_MODIFICATIONS, original sizes preserved"
        },
        "DROP": {
            "icon": "❌",
            "action": "Intercepts and drops all target TCP messages",
            "expected": "Messages logged with red cross indicators, communication blocked, all TCP retransmissions shown"
        }
    }
    
    if mode in mode_descriptions:
        desc = mode_descriptions[mode]
        print(f"{desc['icon']} Action: {desc['action']}")
        print(f"📋 Expected: {desc['expected']}")
    
    print(f"\n💡 Current configuration:")
    print(f"   TCP_ATTACK_MODE = '{mode}'")
    print(f"   Target 1: {AttackConfig.POISON_TARGET_1}")
    print(f"   Target 2: {AttackConfig.POISON_TARGET_2}")
    print(f"   Ports: {AttackConfig.SOCKET_PORTS}")
    
    if mode == "TAMPER":
        print(f"   Modifications: {AttackConfig.SOCKET_MODIFICATIONS}")
    
    print(f"\n🚀 To test this mode:")
    print(f"   1. Run: sudo python3 bidirectional_tcp_interceptor.py")
    print(f"   2. On target device 1, run: python3 tcp_server.py")
    print(f"   3. On target device 2, run: python3 tcp_client.py")
    print(f"   4. Send test messages and observe the {mode} behavior")
    
    return True

def show_mode_comparison():
    """Show comparison of all three modes"""
    print("\n" + "="*80)
    print("📊 TCP ATTACK MODE COMPARISON")
    print("="*80)
    
    print("┌─────────────┬──────────────────────────────────────────────────────────────┐")
    print("│    MODE     │                        BEHAVIOR                              │")
    print("├─────────────┼──────────────────────────────────────────────────────────────┤")
    print("│ 👁️  MONITOR  │ • Logs all intercepted messages with timestamps             │")
    print("│             │ • No packet modification or blocking                        │")
    print("│             │ • Clean, uncluttered logs for surveillance                  │")
    print("│             │ • All communication flows normally                          │")
    print("├─────────────┼──────────────────────────────────────────────────────────────┤")
    print("│ 🔧 TAMPER   │ • Modifies messages according to SOCKET_MODIFICATIONS       │")
    print("│             │ • Preserves original packet sizes for TCP stability         │")
    print("│             │ • Logs original and modified messages                       │")
    print("│             │ • Communication continues with altered content              │")
    print("├─────────────┼──────────────────────────────────────────────────────────────┤")
    print("│ ❌ DROP     │ • Intercepts and discards all target messages               │")
    print("│             │ • Logs dropped packets with red cross indicators            │")
    print("│             │ • Completely blocks communication between targets           │")
    print("│             │ • Effective denial-of-service attack                        │")
    print("│             │ • Shows all TCP retransmission attempts being blocked       │")
    print("└─────────────┴──────────────────────────────────────────────────────────────┘")

def quick_mode_switch():
    """Interactively switch between modes"""
    print("\n🔄 QUICK MODE SWITCHER")
    print("="*50)
    
    current_mode = AttackConfig.TCP_ATTACK_MODE
    print(f"Current mode: {current_mode}")
    
    print("\nAvailable modes:")
    print("1. 👁️  MONITOR - Log only")
    print("2. 🔧 TAMPER - Modify messages") 
    print("3. ❌ DROP - Block communication")
    print("4. 📊 Show comparison")
    print("5. 🚪 Exit")
    
    while True:
        try:
            choice = input("\n🤔 Select mode (1-5): ").strip()
            
            if choice == "1":
                AttackConfig.TCP_ATTACK_MODE = "MONITOR"
                print("✅ Switched to MONITOR mode")
                test_mode("MONITOR")
                break
            elif choice == "2":
                AttackConfig.TCP_ATTACK_MODE = "TAMPER"
                print("✅ Switched to TAMPER mode")
                test_mode("TAMPER")
                break
            elif choice == "3":
                AttackConfig.TCP_ATTACK_MODE = "DROP"
                print("✅ Switched to DROP mode")
                test_mode("DROP")
                break
            elif choice == "4":
                show_mode_comparison()
            elif choice == "5":
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select 1-5.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break

def main():
    """Main function"""
    print("🧪 TCP Attack Mode Testing Tool")
    print("="*50)
    print("This tool helps you understand and test the three TCP attack modes:")
    print("• 👁️  MONITOR: Passive logging")
    print("• 🔧 TAMPER: Active modification") 
    print("• ❌ DROP: Blocking/DoS")
    print()
    
    if len(sys.argv) > 1:
        mode = sys.argv[1].upper()
        if mode in ["MONITOR", "TAMPER", "DROP"]:
            test_mode(mode)
        else:
            print(f"❌ Unknown mode: {mode}")
            print("💡 Usage: python3 test_tcp_modes.py [MONITOR|TAMPER|DROP]")
    else:
        show_mode_comparison()
        quick_mode_switch()

if __name__ == "__main__":
    main() 