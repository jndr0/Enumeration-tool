from scapy.all import ARP, Ether, srp

def arp_ping(network_cidr):
    """
    Realiza un escaneo ARP para detectar hosts activos en una red local.
    :param network_cidr: Ejemplo: "192.168.1.0/24"
    :return: Lista de diccionarios con IP y MAC
    """
    print(f"[+] Escaneando red {network_cidr} con ARP...")
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices
