#!/usr/bin/env python3
"""
Device Loader Module for Unified Attack System
Loads pre-scanned devices from JSON file created by scanner.py
"""

import json
import os
from datetime import datetime
from colorama import Fore, Style

from common.utils import (
    print_section_header, get_user_choice, 
    format_device_info, confirm_action, print_info, print_error, print_success
)

class DeviceLoader:
    """Simple device loader that reads from scanner.py output"""
    
    def __init__(self, scan_file="latest_scan.json"):
        self.scan_file = scan_file
        self.devices = {}
        self.device_list = []
    
    def load_devices(self):
        """Load devices from the JSON file created by scanner.py"""
        if not os.path.exists(self.scan_file):
            print_error(f"Scan file '{self.scan_file}' not found!")
            print_info("Please run scanner.py first to generate device data:")
            print_info(f"  sudo python3 scanner.py")
            return None
        
        try:
            with open(self.scan_file, 'r') as f:
                data = json.load(f)
            
            # Extract devices from the JSON structure
            self.devices = data.get('devices', {})
            
            if not self.devices:
                print_error("No devices found in scan file!")
                return None
            
            # Convert to list format for easy selection
            self.device_list = []
            for ip, device_info in self.devices.items():
                device = dict(device_info)  # Make a copy
                device['ip'] = ip  # Ensure IP is included
                self.device_list.append(device)
            
            # Sort devices by IP for consistent display
            self.device_list.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
            
            # Show scan info
            scan_time = data.get('timestamp', 'Unknown')
            if scan_time != 'Unknown':
                try:
                    scan_dt = datetime.fromisoformat(scan_time)
                    scan_time_str = scan_dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    scan_time_str = scan_time
            else:
                scan_time_str = 'Unknown'
            
            print_success(f"Loaded {len(self.device_list)} devices from previous scan")
            print_info(f"Scan performed: {scan_time_str}")
            
            # Display devices
            self.display_devices()
            
            return self.device_list
            
        except Exception as e:
            print_error(f"Error loading scan file: {e}")
            return None
    
    def display_devices(self):
        """Display loaded devices in a formatted list"""
        print_section_header("📡 LOADED NETWORK DEVICES", Fore.GREEN)
        
        for i, device in enumerate(self.device_list, 1):
            format_device_info(device, i)
            if i < len(self.device_list):  # Add separator except for last device
                print()
        
        print(f"\n{Fore.CYAN}💡 Total devices: {len(self.device_list)}{Style.RESET_ALL}")
        
        # Show device type summary
        device_types = {}
        for device in self.device_list:
            dtype = device.get('device_type', 'unknown')
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        print(f"\n{Fore.YELLOW}📊 Device types:{Style.RESET_ALL}")
        for dtype, count in sorted(device_types.items()):
            # Find an icon for this device type
            icon = '❓'
            for device in self.device_list:
                if device.get('device_type') == dtype and device.get('icon'):
                    icon = device['icon']
                    break
            print(f"   {icon} {dtype.title()}: {count}")
    
    def select_device(self, purpose, exclude_devices=None):
        """Allow user to select a device for a specific purpose"""
        exclude_devices = exclude_devices or []
        
        print_section_header(f"🎯 SELECT DEVICE FOR: {purpose.upper()}", Fore.CYAN)
        
        # Show available devices (excluding already selected ones) with original numbering
        available_device_numbers = []
        print(f"{Fore.YELLOW}Available devices:{Style.RESET_ALL}\n")
        
        for i, device in enumerate(self.device_list, 1):
            if device not in exclude_devices:
                available_device_numbers.append(i)
                format_device_info(device, i)
                print()
        
        if not available_device_numbers:
            print_error("No available devices for selection!")
            return None
        
        # Get user choice - use custom input handling for non-sequential numbers
        print(f"{Fore.CYAN}Select device number for {purpose}:{Style.RESET_ALL}")
        
        valid_choices_display = ", ".join(str(num) for num in available_device_numbers)
        
        while True:
            try:
                choice = input(f"{Fore.YELLOW}Enter device number ({valid_choices_display}) or 'q' to quit: {Style.RESET_ALL}").strip()
                
                if choice.lower() in ['q', 'quit', 'exit']:
                    return None
                
                choice_int = int(choice)
                if choice_int in available_device_numbers:
                    selected_device_number = choice_int
                    selected_device = self.device_list[selected_device_number - 1]  # Convert to 0-based index
                    break
                else:
                    print(f"{Fore.RED}❌ Please enter one of the available device numbers: {valid_choices_display}{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}❌ Please enter a valid number{Style.RESET_ALL}")
            except KeyboardInterrupt:
                return None
        
        # Confirm selection
        print(f"\n{Fore.GREEN}Selected device for {purpose}:{Style.RESET_ALL}")
        format_device_info(selected_device, selected_device_number)
        
        if not confirm_action(f"Confirm {purpose} selection?", default_yes=True):
            return self.select_device(purpose, exclude_devices)
        
        return selected_device
    
    def select_multiple_devices(self, roles):
        """Select multiple devices for different roles"""
        selected_devices = {}
        exclude_list = []
        
        for role in roles:
            device = self.select_device(role, exclude_list)
            if device is None:
                print_error(f"Device selection cancelled for {role}")
                return None
            
            selected_devices[role] = device
            exclude_list.append(device)
            
            # Show progress
            print(f"\n{Fore.GREEN}✅ {role.replace('_', ' ').title()} selected: {device['ip']}{Style.RESET_ALL}")
            self.display_selection_summary(selected_devices, roles)
        
        return selected_devices
    
    def display_selection_summary(self, selected_devices, all_roles):
        """Display summary of selected devices"""
        print_section_header("📋 DEVICE SELECTION SUMMARY", Fore.GREEN)
        
        for role in all_roles:
            if role in selected_devices:
                device = selected_devices[role]
                print(f"\n{Fore.CYAN}{role.upper()}:{Style.RESET_ALL}")
                format_device_info(device)
            else:
                print(f"\n{Fore.YELLOW}{role.upper()}: {Fore.RED}Not selected yet{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Progress: {len(selected_devices)}/{len(all_roles)} devices selected{Style.RESET_ALL}")
    
    def validate_device_selection(self, selected_devices, requirements):
        """Validate that selected devices meet attack requirements"""
        validation_errors = []
        
        # Check that all required roles are filled
        for role in requirements.get('required_roles', []):
            if role not in selected_devices:
                validation_errors.append(f"Missing device for role: {role}")
        
        # Check that no device is used twice (unless allowed)
        if not requirements.get('allow_duplicate_devices', False):
            used_ips = []
            for role, device in selected_devices.items():
                if device['ip'] in used_ips:
                    validation_errors.append(f"Device {device['ip']} selected for multiple roles")
                used_ips.append(device['ip'])
        
        # Check device types if specified
        type_requirements = requirements.get('device_types', {})
        for role, required_types in type_requirements.items():
            if role in selected_devices:
                device_type = selected_devices[role].get('device_type', 'unknown')
                if device_type not in required_types:
                    validation_errors.append(
                        f"{role} device type '{device_type}' not in allowed types: {required_types}"
                    )
        
        # Check MAC addresses are known
        for role, device in selected_devices.items():
            mac = device.get('mac', 'Unknown')
            if mac == 'Unknown' or not mac:
                validation_errors.append(f"{role} device has unknown MAC address")
        
        return validation_errors

def main():
    """Test the device loader module"""
    loader = DeviceLoader()
    
    devices = loader.load_devices()
    if devices:
        print("\nTesting device selection...")
        gateway = loader.select_device("Gateway")
        if gateway:
            victim = loader.select_device("Victim", [gateway])
            if victim:
                print(f"\nSelected Gateway: {gateway['ip']}")
                print(f"Selected Victim: {victim['ip']}")

if __name__ == "__main__":
    main() 