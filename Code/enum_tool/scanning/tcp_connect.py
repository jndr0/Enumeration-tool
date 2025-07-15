import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1):
            return port
    except:
        return None

def tcp_connect_scan(ip, start_port, end_port):
    print(f"[+] Escaneando puertos en {ip} (TCP Connect)...")
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports
