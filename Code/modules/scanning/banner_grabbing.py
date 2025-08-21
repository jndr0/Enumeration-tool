import socket
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Estilo estándar
INFO = Fore.CYAN + "[+]" + Style.RESET_ALL
OK   = Fore.GREEN + "[✓]" + Style.RESET_ALL
ERROR = Fore.RED + "[-]" + Style.RESET_ALL

def grab_banner(ip, port):
    """Intenta obtener el banner de un servicio TCP en un puerto específico."""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return None

def run(ip, ports):
    """
    Ejecuta grab_banner para una IP y lista de puertos.
    - ip: dirección IP del host
    - ports: int o lista de puertos
    """
    if isinstance(ports, int):
        ports = [ports]

    print(f"{Fore.YELLOW}[+] Escaneando banners en {ip}{Style.RESET_ALL}")
    for port in ports:
        banner = grab_banner(ip, port)
        if banner:
            print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {OK} Banner:\n{banner}\n")
        else:
            print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {ERROR} Sin respuesta/banner\n")
