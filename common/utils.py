#!/usr/bin/env python3
"""
Common utility functions for the unified attack system
"""

import os
import sys
import re
from colorama import Fore, Back, Style

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the main system banner"""
    print(f"""{Fore.RED}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    🛡️  UNIFIED ARP SPOOFING & MITM ATTACK SYSTEM  🛡️                  ║
║                                                                      ║
║    📡 Network Discovery  🎯 Attack Selection  ⚙️  Auto-Configuration  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def print_section_header(title, color=Fore.CYAN):
    """Print a formatted section header"""
    print(f"\n{color}{'═' * 70}")
    print(f"  {title}")
    print(f"{'═' * 70}{Style.RESET_ALL}")

def get_user_input(prompt, color=Fore.YELLOW):
    """Get user input with colored prompt"""
    return input(f"{color}{prompt}{Style.RESET_ALL}")

def get_user_choice(prompt, choices, color=Fore.YELLOW):
    """Get user choice from a list of options"""
    while True:
        try:
            choice = input(f"{color}{prompt}{Style.RESET_ALL}").strip()
            
            if choice.lower() in ['q', 'quit', 'exit']:
                return None
            
            choice_int = int(choice)
            if 1 <= choice_int <= len(choices):
                return choice_int - 1
            else:
                print(f"{Fore.RED}❌ Please enter a number between 1 and {len(choices)}{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}❌ Please enter a valid number{Style.RESET_ALL}")
        except KeyboardInterrupt:
            return None

def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    return False

def validate_mac(mac):
    """Validate MAC address format"""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(pattern, mac) is not None

def format_device_info(device, index=None):
    """Format device information for display"""
    if index is not None:
        prefix = f"{Fore.BLUE}[{index:2d}]{Style.RESET_ALL}"
    else:
        prefix = f"{Fore.BLUE}•{Style.RESET_ALL}"
    
    # Device type icon
    icons = {
        'laptop': '💻',
        'phone': '📱',
        'tablet': '📟',
        'router': '🌐',
        'desktop': '🖥️',
        'printer': '🖨️',
        'tv': '📺',
        'unknown': '❓'
    }
    icon = icons.get(device.get('device_type', 'unknown'), '❓')
    
    # Format device info
    name = device.get('hostname', 'Unknown')
    ip = device['ip']
    mac = device.get('mac', 'Unknown')
    vendor = device.get('vendor', 'Unknown')
    device_type = device.get('device_type', 'unknown').title()
    
    print(f"  {prefix} {icon} {device_type}")
    print(f"      📍 IP: {Fore.GREEN}{ip}{Style.RESET_ALL}")
    print(f"      🏷️  Name: {Fore.CYAN}{name}{Style.RESET_ALL}")
    print(f"      🔧 Vendor: {Fore.MAGENTA}{vendor[:30]}{Style.RESET_ALL}")
    print(f"      📝 MAC: {Fore.YELLOW}{mac}{Style.RESET_ALL}")

def confirm_action(message, default_yes=False):
    """Ask for user confirmation"""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    response = input(f"{Fore.YELLOW}{message} {suffix}: {Style.RESET_ALL}").strip().lower()
    
    if not response:
        return default_yes
    
    return response in ['y', 'yes']

def print_error(message):
    """Print an error message"""
    print(f"{Fore.RED}❌ {message}{Style.RESET_ALL}")

def print_success(message):
    """Print a success message"""
    print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")

def print_warning(message):
    """Print a warning message"""
    print(f"{Fore.YELLOW}⚠️  {message}{Style.RESET_ALL}")

def print_info(message):
    """Print an info message"""
    print(f"{Fore.CYAN}ℹ️  {message}{Style.RESET_ALL}")

def wait_for_keypress(message="Press Enter to continue..."):
    """Wait for user to press a key"""
    input(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

def format_time(seconds):
    """Format time duration"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

class ProgressBar:
    """Simple progress bar for long operations"""
    def __init__(self, total, width=50):
        self.total = total
        self.width = width
        self.current = 0
    
    def update(self, increment=1):
        self.current += increment
        self.display()
    
    def display(self):
        percentage = self.current / self.total
        filled = int(self.width * percentage)
        bar = '█' * filled + '░' * (self.width - filled)
        print(f"\r{Fore.CYAN}Progress: [{bar}] {percentage*100:.1f}%{Style.RESET_ALL}", end='', flush=True)
    
    def finish(self):
        print()  # New line after progress bar 