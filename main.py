#!/usr/bin/env python3
"""
Unified ARP Spoofing and MITM Attack System
Main entry point for the simplified user experience
"""

import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import modules
from device_loader import DeviceLoader
from attack_manager import AttackManager
from common.utils import clear_screen, print_banner, print_error, print_success

def main():
    """Main function orchestrating the attack workflow"""
    
    # Print initial banner
    clear_screen()
    print_banner()
    
    print(f"{Fore.CYAN}🎯 UNIFIED ARP SPOOFING & MITM ATTACK SYSTEM{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}═" * 60 + f"{Style.RESET_ALL}")
    print(f"{Fore.WHITE}This system provides a simplified workflow for network attacks:{Style.RESET_ALL}")
    print(f"  1. Load pre-scanned network devices")
    print(f"  2. Select attack type from 7 available options")
    print(f"  3. Assign device roles based on attack requirements")
    print(f"  4. Execute the configured attack")
    print(f"{Fore.YELLOW}═" * 60 + f"{Style.RESET_ALL}")
    
    # Step 1: Load network devices
    print(f"\n{Fore.CYAN}📡 STEP 1: LOAD NETWORK DEVICES{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}═" * 60 + f"{Style.RESET_ALL}")
    
    # Initialize and load devices from previous scan
    loader = DeviceLoader()
    devices = loader.load_devices()
    
    if not devices:
        print(f"{Fore.RED}❌ No devices loaded. Please run scanner.py first:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  sudo python3 scanner.py{Style.RESET_ALL}")
        return
    
    # Step 2: Attack type selection
    print(f"\n{Fore.CYAN}🎯 STEP 2: ATTACK TYPE SELECTION{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}═" * 60 + f"{Style.RESET_ALL}")
    
    # Show attack options
    attack_manager = AttackManager(devices, loader)
    attack_type = attack_manager.select_attack_type()
    
    if not attack_type:
        print(f"{Fore.RED}❌ Attack selection cancelled.{Style.RESET_ALL}")
        return
    
    # Step 3: Device role assignment
    print(f"\n{Fore.CYAN}⚙️  STEP 3: DEVICE ROLE ASSIGNMENT{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}═" * 60 + f"{Style.RESET_ALL}")
    
    # Configure attack with device roles
    attack_config = attack_manager.configure_attack(attack_type)
    
    if not attack_config:
        print(f"{Fore.RED}❌ Attack configuration cancelled.{Style.RESET_ALL}")
        return
    
    # Step 4: Execute attack
    # clear_screen()
    # print_banner()
    
    print(f"\n{Fore.GREEN}🚀 STEP 4: ATTACK EXECUTION{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}═" * 60 + f"{Style.RESET_ALL}")
    
    # Execute the configured attack
    success = attack_manager.execute_attack(attack_type, attack_config)
    
    if success:
        print_success("Attack executed successfully!")
    else:
        print_error("Attack execution failed!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 Program interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1) 