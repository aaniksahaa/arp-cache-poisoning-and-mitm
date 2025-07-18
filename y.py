from scapy.all import ARP, Ether, sendp

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, interface):
    """
    Restore the ARP tables of victim and gateway by sending correct ARP replies.
    """
    print("[*] Restoring ARP tables...")

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


restore_arp(victim_ip="192.168.0.105",
            victim_mac="9a:be:d0:91:f3:76",
            gateway_ip="192.168.0.1",
            gateway_mac="40:ed:00:4a:67:44",
            interface="wlo1")
