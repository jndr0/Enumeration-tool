from scapy.all import IP, TCP, sr1
from colorama import Fore, Style, init

init(autoreset=True)

def detect_os(ip):
    pkt = IP(dst=ip)/TCP(dport=80, flags='S')
    resp = sr1(pkt, timeout=2, verbose=0)

    if resp:
        ttl = resp.ttl
        window = resp[TCP].window
        if ttl <= 64:
            os_guess = "Linux/Unix (probable)"
        elif ttl <= 128:
            os_guess = "Windows (probable)"
        else:
            os_guess = "Desconocido"

        return {"ip": ip, "ttl": ttl, "window": window, "os_guess": os_guess}
    else:
        return {"ip": ip, "error": "Sin respuesta"}

def run(targets):
    """
    Ejecuta la detección de SO para una IP o lista de IPs
    """
    if isinstance(targets, str):
        targets = [targets]

    for ip in targets:
        result = detect_os(ip)
        if "error" in result:
            print(f"{Fore.RED}[{ip}] {result['error']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[{ip}]{Style.RESET_ALL} TTL: {result['ttl']}, "
                  f"Window: {result['window']}, OS Guess: {Fore.GREEN}{result['os_guess']}{Style.RESET_ALL}")

