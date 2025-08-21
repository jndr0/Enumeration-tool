import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Estilo estándar
INFO    = Fore.CYAN + "[+]" + Style.RESET_ALL
OK      = Fore.GREEN + "[OK]" + Style.RESET_ALL
WARN    = Fore.YELLOW + "[!]" + Style.RESET_ALL
ERROR   = Fore.RED + "[-]" + Style.RESET_ALL

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
                print(f"{INFO} Escaneando red {target} en puerto {port}...")
                devices = tcp_ping(target, port, timeout, max_workers)
                if devices:
                    for dev in devices:
                        print(f"{OK} Host activo (TCP): {dev}")
                else:
                    print(f"{WARN} No se han detectado hosts activos en la red {target}")
            else:
                ip = tcp_ping_host(target, port, timeout)
                if ip:
                    print(f"{OK} Host activo (TCP): {ip}")
                else:
                    print(f"{ERROR} Host inactivo o sin respuesta en puerto {port}: {target}")
        except ValueError:
            print(f"{ERROR} Formato de IP o red no válido: {target}")
