from scapy.all import ARP, Ether, srp

#   command
#   sudo /home/aaniksahaa/miniconda3/bin/python3 get-mac-from-ip.py
#   sudo $(which python3) get-mac-from-ip.py

def get_mac(ip_address):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_address)
    # Create an Ethernet frame to broadcast the ARP request
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request
    packet = ether_frame / arp_request
    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=False)[0]
    
    # Check if a response was received
    if result:
        # Extract and return the MAC address from the response
        return result[0][1].hwsrc
    else:
        return None

# Replace with your phone's IP address
phone_ip = "192.168.0.201"
mac_address = get_mac(phone_ip)

if mac_address:
    print(f"MAC address of {phone_ip}: {mac_address}")
else:
    print(f"No response from {phone_ip}. Ensure the device is on the same network and try again.")