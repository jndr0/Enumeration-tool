import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from colorama import Fore, Style, init

init(autoreset=True)

def tcp_ping_host(ip, port=80):
    try:
        with socket.create_connection((str(ip), port), timeout=0.3):
            return str(ip)
    except:
        return None

def tcp_ping(network_cidr, port=80):
    print(f"{Fore.YELLOW}[+] Escaneando red {network_cidr} con TCP Ping en puerto {port}...{Style.RESET_ALL}")
    ip_net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(ip_net.hosts())
    activos = []

    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(lambda ip: tcp_ping_host(ip, port), hosts)

    for ip in results:
        if ip:
            activos.append(ip)

    return activos

def run(target, port=80):
    try:
        # Detectar si es red o IP individual
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            # Es una red
            devices = tcp_ping(target, port)
            if devices:
                for dev in devices:
                    print(f"{Fore.GREEN}[✓] Host activo (TCP): {dev}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No se han detectado hosts activos en la red usando TCP Ping.{Style.RESET_ALL}")
        else:
            # Es una IP individual
            ip = tcp_ping_host(target, port)
            if ip:
                print(f"{Fore.GREEN}[✓] Host activo (TCP): {ip}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Host inactivo o sin respuesta en puerto {port}: {target}{Style.RESET_ALL}")
    except ValueError:
        print(f"{Fore.RED}[-] Formato de IP o red no válido: {target}{Style.RESET_ALL}")
