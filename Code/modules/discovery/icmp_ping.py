from scapy.all import ICMP, IP, sr1
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import time

init(autoreset=True)

def icmp_ping_host(ip, timeout=1):
    """Envía un ping ICMP a un host y devuelve la IP si responde."""
    pkt = IP(dst=str(ip)) / ICMP()
    start = time.time()
    try:
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp:
            rtt = (time.time() - start) * 1000  # ms
            return str(ip), round(rtt, 2)
    except PermissionError:
        print(f"{Fore.RED}[-] Necesitas ejecutar como administrador/root para usar ICMP.{Style.RESET_ALL}")
    return None

def icmp_ping(network_cidr, timeout=1):
    """Escanea todos los hosts de una red con ICMP."""
    print(f"{Fore.YELLOW}[+] Escaneando red {network_cidr} con ICMP Ping ...{Style.RESET_ALL}")
    active_hosts = []

    ip_net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(ip_net.hosts())

    with ThreadPoolExecutor(max_workers=200) as executor:
        results = executor.map(lambda ip: icmp_ping_host(ip, timeout), hosts)

    for result in results:
        if result:
            active_hosts.append(result)

    return active_hosts

def run(target):
    """Detecta si es red o IP y realiza el escaneo."""
    try:
        net = ipaddress.ip_network(target, strict=False)

        if net.num_addresses > 1:  # Red
            devices = icmp_ping(target)
            if devices:
                for ip, rtt in devices:
                    print(f"{Fore.GREEN}[✓] Host activo: {ip} - RTT: {rtt} ms{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No se han detectado hosts activos en la red.{Style.RESET_ALL}")

        else:  # IP individual
            result = icmp_ping_host(target)
            if result:
                ip, rtt = result
                print(f"{Fore.GREEN}[✓] Host activo: {ip} - RTT: {rtt} ms{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Host inactivo o sin respuesta: {target}{Style.RESET_ALL}")

    except ValueError:
        print(f"{Fore.RED}[-] Formato de IP o red no válido: {target}{Style.RESET_ALL}")
