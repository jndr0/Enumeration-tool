import socket
import re
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

INFO = Fore.CYAN + "[+]" + Style.RESET_ALL
OK   = Fore.GREEN + "[✓]" + Style.RESET_ALL
ERROR = Fore.RED + "[-]" + Style.RESET_ALL
WARN = Fore.YELLOW + "[!]" + Style.RESET_ALL

socket.setdefaulttimeout(2)

def grab_banner(ip, port):
    """Obtiene el banner de un servicio TCP"""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            if port in [80, 8080, 8000, 8888]:  # HTTP
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                s.sendall(request.encode())
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return None

def http_header_fingerprint(ip, port):
    """Evalúa cabeceras HTTP para obtener versión de software"""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(4096).decode(errors="ignore")

            match = re.search(r"Server:\s*([^\r\n]*)", response, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            elif "HTTP/" in response:
                return "HTTP service detected, no version info"
            else:
                return None
    except Exception:
        return None

def detect_service(ip, port):
    """Detecta servicio y, si es HTTP, obtiene versión"""
    http_ports = [80, 8080, 8000, 8888, 443]

    if port in http_ports:
        http_result = http_header_fingerprint(ip, port)
        if http_result:
            return f"HTTP Server: {http_result}"

    banner = grab_banner(ip, port)
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return f"SSH Server: {banner}"
        elif "ftp" in banner_lower:
            return f"FTP Server: {banner}"
        elif "smtp" in banner_lower:
            return f"SMTP Server: {banner}"
        elif "telnet" in banner_lower:
            return f"Telnet Server: {banner}"
        elif "pop3" in banner_lower:
            return f"POP3 Server: {banner}"
        elif "imap" in banner_lower:
            return f"IMAP Server: {banner}"
        elif "mysql" in banner_lower:
            return f"MySQL Server: {banner}"
        elif "microsoft" in banner_lower or "iis" in banner_lower:
            return f"Microsoft Service: {banner}"
        else:
            return f"Unknown service (banner): {banner}"

    

def detect_services(ip, ports):
    """Detecta servicios en una lista de puertos y muestra resultados con colores"""
    results = {}
    print(f"{INFO} Iniciando detección de servicios en {ip}")
    for port in ports:
        service_info = detect_service(ip, port)
        results[port] = service_info
        if service_info:
            print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {OK} {service_info}")
    return results
