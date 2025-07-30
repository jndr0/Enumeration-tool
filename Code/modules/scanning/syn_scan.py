from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor

def syn_scan_port(ip, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags='S')
    resp = sr1(pkt, timeout=0.5, verbose=0)
    if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
        return port
    return None

def syn_scan(ip, start_port, end_port):
    print(f"[+] Realizando SYN Scan sobre {ip} ...")
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=500) as executor:
        results = executor.map(lambda p: syn_scan_port(ip, p), ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports
