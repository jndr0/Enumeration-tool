import socket
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Estilos
INFO = Fore.CYAN + "[+]" + Style.RESET_ALL
OK   = Fore.GREEN + "[✓]" + Style.RESET_ALL
ERROR = Fore.RED + "[-]" + Style.RESET_ALL
WARN = Fore.YELLOW + "[!]" + Style.RESET_ALL

def run(target, start_port, end_port):
    """
    Escanea puertos TCP en un rango específico.
    - target: IP del host a escanear
    - start_port: puerto inicial
    - end_port: puerto final
    """
    print(f"{INFO} Escaneando puertos del {start_port} al {end_port} en {target}...\n")

    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Fore.CYAN}[{target}:{port}]{Style.RESET_ALL} {OK} Puerto abierto")
                open_ports.append(port)
            sock.close()
        except KeyboardInterrupt:
            print(f"\n{ERROR} Escaneo interrumpido por el usuario.")
            break
        except Exception as e:
            print(f"{Fore.CYAN}[{target}:{port}]{Style.RESET_ALL} {ERROR} Error: {e}")

    if not open_ports:
        print(f"{WARN} No se encontraron puertos abiertos.")
    else:
        print(f"\n{INFO} Total puertos abiertos: {len(open_ports)}")
