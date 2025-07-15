from scapy.all import IP, TCP, sr
from concurrent.futures import ThreadPoolExecutor

def syn_scan(ip, start_port, end_port):
    print(f"[+] Realizando SYN Scan sobre {ip} (puertos {start_port}-{end_port})...")
    open_ports = []
    ports = range(start_port, end_port + 1)
    packets = [IP(dst=ip)/TCP(dport=p, flags='S') for p in ports]

    answered, _ = sr(packets, timeout=2, verbose=0)

    for send, recv in answered:
        if recv.haslayer(TCP) and recv[TCP].flags == 0x12:  # SYN-ACK
            open_ports.append(recv[TCP].sport)

    return open_ports
