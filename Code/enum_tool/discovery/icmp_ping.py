from scapy.all import ICMP, IP, sr1
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def icmp_ping_host(ip):
    pkt = IP(dst=str(ip))/ICMP()
    resp = sr1(pkt, timeout=1, verbose=False)
    if resp:
        return str(ip)
    return None

def icmp_ping(network_cidr):
    print(f"[+] Escaneando red {network_cidr} con ICMP Ping...")
    active_hosts = []

    ip_net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(ip_net.hosts())

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(icmp_ping_host, hosts)

    for ip in results:
        if ip:
            active_hosts.append(ip)

    return active_hosts
