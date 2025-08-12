import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from colorama import Fore, Style, init

init(autoreset=True)

def tcp_ping_host(ip, port=80, timeout=0.3):
    """Comprueba si un host responde en un puerto TCP específico."""
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return str(ip)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def tcp_ping(network_cidr, port=80, timeout=0.3, max_workers=500):
    """Escanea una red CIDR completa para ver qué hosts responden en un puerto TCP."""
    ip_net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(ip_net.hosts())
    activos = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda ip: tcp_ping_host(ip, port, timeout), hosts)

    for ip in results:
        if ip:
            activos.append(ip)

    return activos

def run(targets, port=80, timeout=0.3, max_workers=500):
    """
    targets puede ser:
    - Una IP individual: "192.168.1.10"
    - Una red CIDR: "192.168.1.0/24"
    - Varias IPs o redes separadas por comas: "192.168.1.10,192.168.1.15,10.0.0.0/30"
    """
    for target in targets.split(","):
        target = target.strip()
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 1:
                print(f"{Fore.YELLOW}[+] Escaneando red {target} en puerto {port}...{Style.RESET_ALL}")
                devices = tcp_ping(target, port, timeout, max_workers)
                if devices:
                    for dev in devices:
                        print(f"{Fore.GREEN}[✓] Host activo (TCP): {dev}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] No se han detectado hosts activos en la red {target}{Style.RESET_ALL}")
            else:
                ip = tcp_ping_host(target, port, timeout)
                if ip:
                    print(f"{Fore.GREEN}[✓] Host activo (TCP): {ip}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Host inactivo o sin respuesta en puerto {port}: {target}{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[-] Formato de IP o red no válido: {target}{Style.RESET_ALL}")

