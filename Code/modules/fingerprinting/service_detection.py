import socket
import re
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Evitar que sockets se cuelguen
socket.setdefaulttimeout(2)

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip()
    except Exception:
        return None

def detect_http(ip, port):
    try:
        with socket.socket() as s:
            s.connect((ip, port))
            http_request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            s.sendall(http_request.encode())
            response = s.recv(2048).decode(errors="ignore")
            match = re.search(r"Server:\s*(.*)", response, re.IGNORECASE)
            if match:
                return f"HTTP Server: {match.group(1)}"
            if "HTTP/" in response:
                return "HTTP service detected, no version info"
            return None
    except Exception:
        return None

def detect_service(ip, port):
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

    if port in [80, 8080, 8000, 8888, 443]:
        result = detect_http(ip, port)
        if result:
            return result

    return "No banner or response detected"

def detect_services(ip, ports):
    """
    Detecta servicios en múltiples puertos y muestra los resultados por pantalla con color.
    :param ip: Dirección IP destino
    :param ports: Lista de puertos a analizar
    :return: Diccionario {puerto: servicio_detectado}
    """
    results = {}
    print(f"{Fore.YELLOW}[+] Iniciando detección de servicios en {ip}{Style.RESET_ALL}")
    for port in ports:
        service_info = detect_service(ip, port)
        results[port] = service_info
        print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {Fore.GREEN}{service_info}{Style.RESET_ALL}")
    return results
