from scapy.all import ARP, Ether, sendp

# Import centralized configuration
from config import NetworkConfig, AttackConfig

def restore_arp(victim_ip=None, victim_mac=None, gateway_ip=None, gateway_mac=None, interface=None):
    """
    Restore the ARP tables of victim and gateway by sending correct ARP replies.
    Uses config values as defaults if parameters not provided.
    """
    # Use config defaults if not provided
    victim_ip = victim_ip or AttackConfig.VICTIM_IP
    victim_mac = victim_mac or AttackConfig.VICTIM_MAC
    gateway_ip = gateway_ip or AttackConfig.GATEWAY_IP
    gateway_mac = gateway_mac or AttackConfig.GATEWAY_MAC
    interface = interface or NetworkConfig.INTERFACE
    
    print("[*] Restoring ARP tables...")
    print(f"    Victim: {victim_ip} -> {victim_mac}")
    print(f"    Gateway: {gateway_ip} -> {gateway_mac}")
    print(f"    Interface: {interface}")

    # Correct ARP reply to victim: gateway IP → gateway MAC
    pkt_to_victim = Ether(dst=victim_mac) / ARP(
        op=2,  # is-at (ARP reply)
        pdst=victim_ip,
        hwdst=victim_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )
    sendp(pkt_to_victim, iface=interface, count=5, verbose=0)

    # Correct ARP reply to gateway: victim IP → victim MAC
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=victim_ip,
        hwsrc=victim_mac
    )
    sendp(pkt_to_gateway, iface=interface, count=5, verbose=0)

    print("[+] ARP tables restored.")

if __name__ == "__main__":
    # Use configuration values
    restore_arp()
