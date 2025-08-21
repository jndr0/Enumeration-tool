from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Estilos
INFO = Fore.CYAN + "[+]" + Style.RESET_ALL
OK   = Fore.GREEN + "[✓]" + Style.RESET_ALL
ERROR = Fore.RED + "[-]" + Style.RESET_ALL

def syn_scan_port(ip, port):
    """Envía paquete SYN a un puerto y devuelve el puerto si está abierto."""
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=0.5, verbose=0)
    if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
        return port
    return None

def run(ip, port_range=None, single_port=None):
    """
    Realiza SYN Scan en una IP.
    - ip: dirección IP del host
    - port_range: rango de puertos en formato "start-end"
    - single_port: puerto individual
    """
    if single_port:
        ports = [single_port]
    elif port_range:
        start_port, end_port = map(int, port_range.split("-"))
        ports = range(start_port, end_port + 1)
    else:
        ports = range(1, 1025)  # Rango por defecto

    print(f"{INFO} Realizando SYN Scan sobre {ip}...")

    open_ports = []
    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(lambda p: syn_scan_port(ip, p), ports)

    for port in results:
        if port:
            print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {OK} Puerto abierto")
            open_ports.append(port)

    if not open_ports:
        print(f"{ERROR} No se encontraron puertos abiertos en {ip}.")
    else:
        print(f"{INFO} Total puertos abiertos en {ip}: {len(open_ports)}")
