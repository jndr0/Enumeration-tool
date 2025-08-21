from scapy.all import IP, TCP, ICMP, sr1
from colorama import Fore, Style, init
import time

# Inicializar colorama
init(autoreset=True)

def ack_scan(ip, port, timeout=1):
    """
    Realiza un ACK Scan para detectar si un puerto está filtrado por un firewall.
    Devuelve 'Filtered', 'Unfiltered', 'Filtered (ICMP)' o 'Unknown'.
    """
    try:
        start_time = time.time()

        # Construcción del paquete TCP con flag ACK
        pkt = IP(dst=ip) / TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=timeout, verbose=False)

        elapsed = round((time.time() - start_time) * 1000, 2)  # ms

        if resp is None:
            return f"{Fore.RED}Filtered (no response){Style.RESET_ALL} [{elapsed} ms]"

        if resp.haslayer(TCP):
            tcp_flags = resp.getlayer(TCP).flags
            if tcp_flags == 0x4:  # RST
                return f"{Fore.GREEN}Unfiltered{Style.RESET_ALL} [{elapsed} ms]"
            else:
                return f"{Fore.YELLOW}Unexpected TCP flags={tcp_flags}{Style.RESET_ALL} [{elapsed} ms]"

        if resp.haslayer(ICMP):
            icmp_type = resp.getlayer(ICMP).type
            icmp_code = resp.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                return f"{Fore.RED}Filtered (ICMP type={icmp_type} code={icmp_code}){Style.RESET_ALL} [{elapsed} ms]"
            else:
                return f"{Fore.YELLOW}ICMP response type={icmp_type} code={icmp_code}{Style.RESET_ALL} [{elapsed} ms]"

        return f"{Fore.YELLOW}Unknown response{Style.RESET_ALL} [{elapsed} ms]"

    except Exception as e:
        return f"{Fore.RED}Error: {e}{Style.RESET_ALL}"


def run_ack_scan(ips, ports, timeout=1):
    """
    Ejecuta ACK Scan sobre múltiples IPs y puertos.
    """
    print(f"\n{Fore.YELLOW}[+] Iniciando ACK Scan{Style.RESET_ALL}")
    for ip in ips:
        for port in ports:
            status = ack_scan(ip, port, timeout)
            print(f"{Fore.CYAN}[{ip}:{port}]{Style.RESET_ALL} {status}")
