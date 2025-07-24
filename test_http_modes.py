#!/usr/bin/env python3
"""
Test Script for HTTP Interceptor Modes
Demonstrates MONITOR, TAMPER, and DROP modes for HTTP traffic
"""

import os
import sys
import subprocess
import time
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import config to modify modes
from config import AttackConfig

def print_test_banner():
    """Print test banner"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print("🧪 HTTP INTERCEPTOR MODES - TEST SCRIPT")
    print(f"{'='*70}{Style.RESET_ALL}")

def test_mode(mode):
    """Test a specific HTTP interceptor mode"""
    print(f"\n{Fore.YELLOW}📋 Testing HTTP {mode} Mode{Style.RESET_ALL}")
    print("="*50)
    
    # Update config
    AttackConfig.HTTP_ATTACK_MODE = mode
    
    # Show mode explanation
    if mode == "MONITOR":
        print(f"{Fore.GREEN}👁️  MONITOR Mode - Will log all HTTP traffic without modification{Style.RESET_ALL}")
        print("   • Shows detailed HTTP requests and responses")
        print("   • Perfect for understanding network behavior")
        print("   • No impact on victim browsing")
    elif mode == "TAMPER":
        print(f"{Fore.RED}🔧 TAMPER Mode - Will inject content into HTML responses{Style.RESET_ALL}")
        print("   • Modifies web pages in real-time")
        print("   • Handles gzip compression/decompression")
        print("   • Demonstrates content injection attacks")
    elif mode == "DROP":
        print(f"{Fore.MAGENTA}🗑️  DROP Mode - Will drop all HTTP packets{Style.RESET_ALL}")
        print("   • Prevents victim from browsing HTTP sites")
        print("   • HTTPS traffic remains unaffected")
        print("   • Demonstrates denial-of-service attacks")
    
    print(f"\n{Fore.BLUE}🎯 Current target: {AttackConfig.VICTIM_IP}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}🌐 Gateway: {AttackConfig.GATEWAY_IP}{Style.RESET_ALL}")
    
    # Ask for confirmation
    response = input(f"\n🚀 Start HTTP {mode} mode test? [y/N]: ").strip().lower()
    if response not in ['y', 'yes']:
        print(f"{Fore.YELLOW}⏩ Skipping {mode} mode test{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}🚀 Starting HTTP {mode} mode...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}💡 Test by browsing to http://neverssl.com from victim device{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}🛑 Press Ctrl+C to stop and see statistics{Style.RESET_ALL}")
    
    try:
        # Run the new HTTP interceptor
        subprocess.run([sys.executable, 'new_http_interceptor.py'], check=True)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}✅ {mode} mode test completed{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"\n{Fore.RED}❌ Error running {mode} mode: {e}{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"\n{Fore.RED}❌ new_http_interceptor.py not found{Style.RESET_ALL}")

def print_testing_guide():
    """Print comprehensive testing guide"""
    print(f"\n{Fore.CYAN}🧪 HTTP INTERCEPTOR TESTING GUIDE{Style.RESET_ALL}")
    print("="*50)
    
    print(f"\n{Fore.GREEN}📋 RECOMMENDED TESTING SEQUENCE:{Style.RESET_ALL}")
    print("1. Start with MONITOR mode to see HTTP traffic")
    print("2. Switch to TAMPER mode to test content injection")
    print("3. Try DROP mode to test traffic blocking")
    
    print(f"\n{Fore.YELLOW}🌐 BEST TEST SITES (HTTP-only):{Style.RESET_ALL}")
    print("• http://neverssl.com - Never uses HTTPS")
    print("• http://httpforever.com - Plain HTTP site")
    print("• http://example.com - Simple test site")
    
    print(f"\n{Fore.BLUE}⚠️  IMPORTANT NOTES:{Style.RESET_ALL}")
    print("• Most modern websites use HTTPS (encrypted)")
    print("• HTTPS traffic cannot be intercepted/modified")
    print("• Only HTTP (port 80) traffic will be affected")
    print("• Run with sudo/root privileges for iptables access")
    
    print(f"\n{Fore.MAGENTA}🔧 MANUAL MODE SWITCHING:{Style.RESET_ALL}")
    print("Edit config.py and change:")
    print("AttackConfig.HTTP_ATTACK_MODE = 'MONITOR'  # or 'TAMPER' or 'DROP'")

def check_requirements():
    """Check if requirements are met"""
    print(f"\n{Fore.BLUE}🔍 Checking Requirements...{Style.RESET_ALL}")
    
    issues = []
    
    # Check if running as root
    if os.geteuid() != 0:
        issues.append("⚠️  Not running as root - may need sudo for iptables")
    
    # Check if new_http_interceptor.py exists
    if not os.path.exists('new_http_interceptor.py'):
        issues.append("❌ new_http_interceptor.py not found")
    
    # Check network configuration
    if not AttackConfig.VICTIM_IP or not AttackConfig.GATEWAY_IP:
        issues.append("❌ Network targets not configured in config.py")
    
    if issues:
        print(f"{Fore.YELLOW}⚠️  Issues found:{Style.RESET_ALL}")
        for issue in issues:
            print(f"   {issue}")
        return False
    
    print(f"{Fore.GREEN}✅ All requirements met{Style.RESET_ALL}")
    return True

def main():
    """Main test function"""
    print_test_banner()
    print_testing_guide()
    
    if not check_requirements():
        print(f"\n{Fore.RED}❌ Please fix the issues above before testing{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}🎯 INTERACTIVE MODE TESTING{Style.RESET_ALL}")
    print("Choose modes to test:")
    
    while True:
        print(f"\n{Fore.WHITE}Available modes:{Style.RESET_ALL}")
        print("1. MONITOR - Log HTTP traffic")
        print("2. TAMPER - Inject content")
        print("3. DROP - Block HTTP traffic")
        print("4. Exit")
        
        try:
            choice = input(f"\n{Fore.CYAN}Select mode (1-4): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                test_mode("MONITOR")
            elif choice == '2':
                test_mode("TAMPER")
            elif choice == '3':
                test_mode("DROP")
            elif choice == '4':
                print(f"{Fore.GREEN}👋 Testing complete!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.YELLOW}⚠️  Invalid choice. Please select 1-4.{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}👋 Testing interrupted by user{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 