#!/usr/bin/env python3
"""
MAC Database Loader - Load local MAC vendor JSON database
Utility to import and test MAC vendor databases in JSON format
"""

import json
import sys
from scanner import NetworkDeviceScanner

def load_mac_database_from_file(filename):
    """Load MAC vendor database from a local JSON file"""
    try:
        with open(filename, 'r') as f:
            mac_data = json.load(f)
        
        print(f"✅ Loaded MAC database from {filename}")
        
        # Create scanner instance
        scanner = NetworkDeviceScanner()
        
        # Parse the JSON data
        scanner.parse_json_mac_database(mac_data)
        
        # Save to standard location
        scanner.save_mac_database()
        
        print(f"📊 Processed {len(scanner.mac_vendors)} MAC vendor entries")
        
        if hasattr(scanner, 'mac_vendor_details'):
            print(f"🔍 Enhanced details available for {len(scanner.mac_vendor_details)} vendors")
        
        return scanner
        
    except FileNotFoundError:
        print(f"❌ File {filename} not found")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON format: {e}")
        return None
    except Exception as e:
        print(f"❌ Error loading database: {e}")
        return None

def test_mac_lookups(scanner, test_macs=None):
    """Test MAC address lookups with the loaded database"""
    if not scanner:
        return
    
    if not test_macs:
        # Default test MACs
        test_macs = [
            "00:00:0C:12:34:56",  # Cisco
            "24:b2:b9:3e:22:13",  # Huawei (from your example)
            "60:a4:b7:a9:77:05",  # Netgear (from your example)
            "00:1B:63:12:34:56",  # Apple
            "00:50:56:12:34:56",  # VMware
            "00:0C:29:12:34:56",  # VMware
            "08:00:27:12:34:56",  # VirtualBox
        ]
    
    print(f"\n🧪 TESTING MAC ADDRESS LOOKUPS")
    print(f"{'='*50}")
    
    for mac in test_macs:
        vendor, details = scanner.get_vendor_from_mac(mac)
        print(f"\n📝 MAC: {mac}")
        print(f"🔧 Vendor: {vendor}")
        
        if details:
            if details.get('block_type'):
                print(f"📋 Block Type: {details['block_type']}")
            if details.get('private') is not None:
                privacy = "Private" if details['private'] else "Public"
                print(f"🔒 Registration: {privacy}")
            if details.get('last_update'):
                print(f"📅 Last Updated: {details['last_update']}")
            if details.get('matched_prefix'):
                print(f"🔍 Matched Prefix: {details['matched_prefix']} ({details.get('prefix_length', 0)} chars)")

def show_database_stats(scanner):
    """Show statistics about the loaded database"""
    if not scanner:
        return
    
    print(f"\n📊 DATABASE STATISTICS")
    print(f"{'='*50}")
    print(f"Total MAC prefixes: {len(scanner.mac_vendors)}")
    
    if hasattr(scanner, 'mac_vendor_details'):
        details = scanner.mac_vendor_details
        print(f"Enhanced details: {len(details)}")
        
        # Count block types
        block_types = {}
        private_count = 0
        public_count = 0
        
        for detail in details.values():
            block_type = detail.get('block_type', 'Unknown')
            block_types[block_type] = block_types.get(block_type, 0) + 1
            
            if detail.get('private') is True:
                private_count += 1
            elif detail.get('private') is False:
                public_count += 1
        
        print(f"\n📋 Block Types:")
        for bt, count in sorted(block_types.items(), key=lambda x: x[1], reverse=True):
            print(f"   • {bt}: {count}")
        
        if private_count or public_count:
            print(f"\n🔒 Registration Types:")
            if public_count:
                print(f"   • Public: {public_count}")
            if private_count:
                print(f"   • Private: {private_count}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="MAC Database Loader")
    parser.add_argument("filename", help="JSON file containing MAC vendor database")
    parser.add_argument("--test", action="store_true", help="Run test lookups")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--mac", action="append", help="Test specific MAC address")
    
    args = parser.parse_args()
    
    # Load the database
    scanner = load_mac_database_from_file(args.filename)
    
    if not scanner:
        sys.exit(1)
    
    # Show statistics if requested
    if args.stats:
        show_database_stats(scanner)
    
    # Run tests if requested
    if args.test:
        test_macs = args.mac if args.mac else None
        test_mac_lookups(scanner, test_macs)
    
    print(f"\n✅ MAC database loaded and ready!")
    print(f"📝 Database saved to 'mac_vendors.json' for use with network scanner")

if __name__ == "__main__":
    main() 