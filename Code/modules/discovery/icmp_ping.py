from scapy.all import ICMP, IP, sr1
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

def icmp_ping_host(ip):
    pkt = IP(dst=str(ip))/ICMP()
    resp = sr1(pkt, timeout=0.5, verbose=False)
    if resp:
        return str(ip)
    return None

def icmp_ping(network_cidr):
    print(f"{Fore.YELLOW}[+] Escaneando red {network_cidr} con ICMP Ping ...{Style.RESET_ALL}")
    active_hosts = []

    ip_net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(ip_net.hosts())

    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(icmp_ping_host, hosts)

    for ip in results:
        if ip:
            active_hosts.append(ip)

    return active_hosts

def run(target):
    try:
        # Detectar si es red o IP
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            # Es una red
            devices = icmp_ping(target)
            if devices:
                for dev in devices:
                    print(f"{Fore.GREEN}[✓] Host activo: {dev}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No se han detectado hosts activos en la red.{Style.RESET_ALL}")
        else:
            # Es una IP individual
            ip = icmp_ping_host(target)
            if ip:
                print(f"{Fore.GREEN}[✓] Host activo: {ip}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Host inactivo o sin respuesta: {target}{Style.RESET_ALL}")
    except ValueError:
        print(f"{Fore.RED}[-] Formato de IP o red no válido: {target}{Style.RESET_ALL}")
