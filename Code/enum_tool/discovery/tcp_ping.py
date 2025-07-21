import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress

def tcp_ping_host(ip, port=80):
    try:
        with socket.create_connection((str(ip), port), timeout=0.3):
            return str(ip)
    except:
        return None

def tcp_ping(network_cidr, port=80):
    print(f"[+] Escaneando red {network_cidr} con TCP Ping ...")
    ip_net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(ip_net.hosts())
    activos = []

    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(lambda ip: tcp_ping_host(ip, port), hosts)

    for ip in results:
        if ip:
            activos.append(ip)

    return activos
