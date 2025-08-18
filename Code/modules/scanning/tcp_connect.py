import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

def scan_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.3):
            return port
    except:
        return None

def tcp_connect_scan(ip, start_port, end_port):
    print(f"{Fore.CYAN}[+] Escaneando puertos en {ip} ...{Style.RESET_ALL}")
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for port in results:
        if port:
            print(f"{Fore.GREEN}[+] Puerto abierto: {port}{Style.RESET_ALL}")
            open_ports.append(port)

    if not open_ports:
        print(f"{Fore.RED}[-] No se encontraron puertos abiertos en {ip}{Style.RESET_ALL}")

    return open_ports

def run(targets, start_port, end_port):
    """
    Ejecuta el TCP connect scan para una IP o lista de IPs
    """
    if isinstance(targets, str):
        targets = [targets]

    for ip in targets:
        tcp_connect_scan(ip, start_port, end_port)

