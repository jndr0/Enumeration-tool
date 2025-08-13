from scapy.all import ARP, Ether, srp
import socket

def arp_ping(network_cidr, timeout=1):
    """
    Escaneo ARP para detectar hosts activos en una red local.
    :param network_cidr: Ejemplo: "192.168.1.0/24"
    :param timeout: Tiempo de espera en segundos (default=1)
    :return: Lista de diccionarios con IP y MAC
    """
    print(f"[+] Escaneando red {network_cidr} con ARP...")
    
    try:
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=timeout,promisc=True, verbose=False)[0]
        devices = []

        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': obtener_hostname(received.psrc)
            })

        return devices

    except PermissionError:
        print("[-] Error: necesitas privilegios de administrador/root para ejecutar ARP scan.")
        return []
    except Exception as e:
        print(f"[-] Error inesperado: {e}")
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
            print(f"[✓] Host encontrado: {dev['ip']} - MAC: {dev['mac']} - Hostname: {dev['hostname']}")
    else:
        print("[-] No se han detectado hosts activos.")
