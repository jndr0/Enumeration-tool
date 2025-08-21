import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

INFO = Fore.CYAN + "[+]" + Style.RESET_ALL
OK   = Fore.GREEN + "[✓]" + Style.RESET_ALL
ERROR = Fore.RED + "[-]" + Style.RESET_ALL
WARN = Fore.YELLOW + "[!]" + Style.RESET_ALL

def udp_scan_port(ip, port, timeout=1):
    """
    Intenta enviar un paquete UDP vacío al puerto.
    Si se recibe respuesta ICMP tipo 3/código 3 -> cerrado.
    Si no hay respuesta -> abierto o filtrado.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (ip, port))
        # Esperar respuesta
        try:
            data, _ = sock.recvfrom(1024)
            return f"{OK} Puerto abierto o respondió: {data.decode(errors='ignore')}"
        except socket.timeout:
            return f"{WARN} Puerto abierto/filtrado (sin respuesta)"
        finally:
            sock.close()
    except PermissionError:
        return f"{ERROR} Necesita permisos de administrador/root"
    except Exception as e:
        return f"{ERROR} Error: {e}"

def run_udp_scan(targets, ports, timeout=1, max_workers=200):
    """
    Ejecuta UDP Scan sobre múltiples IPs y puertos
    """
    print(f"{INFO} Iniciando UDP Scan")
    for ip in targets:
        print(f"{INFO} Escaneando {ip}...")
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(udp_scan_port, ip, port, timeout): port for port in ports}
            for future in futures:
                port = futures[future]
                status = future.result()
                results[port] = status
                print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {status}")
        print(f"\n{INFO} Escaneo UDP finalizado para {ip}\n")
