# modules/fingerprinting/service_detection.py

import socket
import re

socket.setdefaulttimeout(2)  # Timeout corto para que no se bloquee

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return banner.strip()
    except Exception:
        return None

def detect_http(ip, port=80):
    try:
        s = socket.socket()
        s.connect((ip, port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
        response = s.recv(2048).decode(errors="ignore")
        s.close()
        # Buscar el header Server
        match = re.search(r"Server:\s*(.*)", response, re.IGNORECASE)
        if match:
            return f"HTTP Server: {match.group(1)}"
        return "HTTP detected, but no Server header"
    except:
        return None

def detect_service(ip, port):
    """Detecta servicio específico según el puerto"""
    service = None
    banner = grab_banner(ip, port)

    if port == 21 and banner:
        service = f"FTP Server: {banner}"
    elif port == 22 and banner:
        service = f"SSH Server: {banner}"
    elif port == 23 and banner:
        service = f"Telnet Server: {banner}"
    elif port == 25 and banner:
        service = f"SMTP Server: {banner}"
    elif port in [80, 8080, 8000]:
        service = detect_http(ip, port)
    else:
        if banner:
            service = f"Unknown service (banner): {banner}"
    
    return service or "No banner or service could be detected"
