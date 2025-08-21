from scapy.all import ARP, Ether, srp
import socket
from colorama import Fore, Style, init as colorama_init

# Inicializar colorama
colorama_init(autoreset=True)

# Estilo estándar
INFO    = Fore.CYAN + "[+]" + Style.RESET_ALL
OK      = Fore.GREEN + "[OK]" + Style.RESET_ALL
WARN    = Fore.YELLOW + "[!]" + Style.RESET_ALL
ERROR   = Fore.RED + "[-]" + Style.RESET_ALL

def arp_ping(network_cidr, timeout=1):
    """
    Escaneo ARP para detectar hosts activos en una red local.
    :param network_cidr: Ejemplo: "192.168.1.0/24"
    :param timeout: Tiempo de espera en segundos (default=1)
    :return: Lista de diccionarios con IP y MAC
    """
    print(f"{INFO} Escaneando red {network_cidr} con ARP...")

    try:
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=timeout, promisc=True, verbose=False)[0]
        devices = []

        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': obtener_hostname(received.psrc)
            })

        return devices

    except PermissionError:
        print(f"{ERROR} Necesitas privilegios de administrador/root para ejecutar ARP scan.")
        return []
    except Exception as e:
        print(f"{ERROR} Error inesperado: {e}")
        return []

def obtener_hostname(ip):
    """Intenta obtener el nombre del host mediante resolución inversa."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Desconocido"

def run(target):
    devices = arp_ping(target)
    if devices:
        for dev in devices:
            print(f"{OK} Host encontrado: {dev['ip']} - MAC: {dev['mac']} - Hostname: {dev['hostname']}")
    else:
        print(f"{WARN} No se han detectado hosts activos.")
