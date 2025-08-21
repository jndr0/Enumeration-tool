import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Estilos
INFO = Fore.CYAN + "[+]" + Style.RESET_ALL
OK   = Fore.GREEN + "[✓]" + Style.RESET_ALL
ERROR = Fore.RED + "[-]" + Style.RESET_ALL

def scan_port(ip, port):
    """Intenta conectarse a un puerto TCP y devuelve el puerto si está abierto."""
    try:
        with socket.create_connection((ip, port), timeout=0.3):
            return port
    except:
        return None

def tcp_connect_scan(ip, start_port, end_port):
    """Escanea un rango de puertos TCP en una IP."""
    print(f"{INFO} Escaneando puertos en {ip} del {start_port} al {end_port} ...")

    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for port in results:
        if port:
            print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {OK} Puerto abierto")
            open_ports.append(port)

    if not open_ports:
        print(f"{ERROR} No se encontraron puertos abiertos en {ip}")

    return open_ports

def run(targets, start_port, end_port):
    """
    Ejecuta TCP Connect Scan sobre una o varias IPs.
    - targets: str o lista de IPs
    - start_port: puerto inicial
    - end_port: puerto final
    """
    if isinstance(targets, str):
        targets = [targets]

    for ip in targets:
        tcp_connect_scan(ip, start_port, end_port)
