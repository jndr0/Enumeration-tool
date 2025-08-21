from scapy.all import IP, TCP, sr1
from colorama import Fore, Style, init

init(autoreset=True)

def detect_os(ip, timeout=2):
    """Detecta el sistema operativo probable a partir de TTL y Window Size."""
    try:
        pkt = IP(dst=ip) / TCP(dport=80, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

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
    except PermissionError:
        return {"ip": ip, "error": "Necesitas ejecutar como administrador/root para enviar paquetes"}
    except Exception as e:
        return {"ip": ip, "error": f"Error desconocido: {e}"}

def run(targets, timeout=2):
    """
    Ejecuta la detección de SO para:
    - Una IP individual -> "192.168.1.10"
    - Varias IPs separadas por comas -> "192.168.1.10,192.168.1.20"
    """
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(",")]

    print(f"{Fore.YELLOW}[+] Iniciando detección de sistema operativo...{Style.RESET_ALL}")

    for ip in targets:
        result = detect_os(ip, timeout)
        if "error" in result:
            print(f"{Fore.RED}[-] {ip} -> {result['error']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[{ip}]{Style.RESET_ALL} "
                  f"TTL: {result['ttl']} | "
                  f"Window: {result['window']} | "
                  f"OS Guess: {Fore.GREEN}{result['os_guess']}{Style.RESET_ALL}")
