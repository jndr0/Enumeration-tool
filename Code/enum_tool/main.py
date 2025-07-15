from colorama import Fore, Style, init
init(autoreset=True)

from discovery.arp_ping import arp_ping
from discovery.icmp_ping import icmp_ping
from discovery.tcp_ping import tcp_ping
from scanning.tcp_connect import tcp_connect_scan

def menu():
    print(Fore.CYAN + "\n=== Herramienta de Escaneo y Enumeración ===")
    print(Fore.YELLOW + "1." + Style.RESET_ALL + " ARP Ping")
    print(Fore.YELLOW + "2." + Style.RESET_ALL + " ICMP Ping")
    print(Fore.YELLOW + "3." + Style.RESET_ALL + " TCP Ping")
    print(Fore.YELLOW + "4." + Style.RESET_ALL + " TCP Connect Scan (Escaneo de puertos)")
    print(Fore.YELLOW + "5." + Style.RESET_ALL + " SYN Scan (Escaneo de puertos con Scapy)")
    print(Fore.YELLOW + "6." + Style.RESET_ALL + " Banner Grabbing")
    print(Fore.YELLOW + "7." + Style.RESET_ALL + " Detección de Sistema Operativo")
    print(Fore.RED + "0." + Style.RESET_ALL + " Salir")
    


def main():
    while True:
        menu()
        choice = input("Selecciona una opción: ")

        if choice == "1":
            net = input("Introduce la red (ej: 192.168.1.0/24): ")
            results = arp_ping(net)
            print("\n[+] Dispositivos encontrados (ARP):")
            for d in results:
                print(f"- IP: {d['ip']} \t MAC: {d['mac']}")
        
        elif choice == "2":
            net = input("Introduce la red (ej: 192.168.1.0/24): ")
            results = icmp_ping(net)
            print("\n[+] Hosts activos (ICMP):")
            for ip in results:
                print(f"- IP: {ip}")
        
        elif choice == "3":
            net = input("Introduce la red (ej: 192.168.1.0/24): ")
            port = int(input("Puerto a usar para TCP Ping (ej: 80): "))
            results = tcp_ping(net, port)
            print(Fore.GREEN + "\n[+] Hosts activos (TCP Ping):")
            for ip in results:
                print(f"- IP: {ip}")

        elif choice == "4":
            target_ip = input("Introduce la IP objetivo (ej: 192.168.1.1): ")
            start_port = int(input("Puerto inicial: "))
            end_port = int(input("Puerto final: "))
            results = tcp_connect_scan(target_ip, start_port, end_port)
            print(Fore.GREEN + f"\n[+] Puertos abiertos en {target_ip}:")
            for port in results:
                print(f"- Puerto {port} abierto")
        elif choice == "5":
            ip = input("IP objetivo: ")
            p1 = int(input("Puerto inicial: "))
            p2 = int(input("Puerto final: "))
            from scanning.syn_scan import syn_scan
            results = syn_scan(ip, p1, p2)
            print(Fore.GREEN + f"[+] Puertos abiertos (SYN Scan):")
            for port in results:
                print(f"- Puerto {port} abierto")

        elif choice == "6":
            ip = input("IP objetivo: ")
            port = int(input("Puerto (ej: 80, 21, 22): "))
            from scanning.banner_grabbing import grab_banner
            banner = grab_banner(ip, port)
            print(Fore.GREEN + f"[+] Banner obtenido:")
            print(banner if banner else "No se recibió respuesta.")

        elif choice == "7":
            ip = input("IP objetivo: ")
            from fingerprinting.os_detect import detect_os
            result = detect_os(ip)
            if "error" in result:
                print(Fore.RED + result["error"])
            else:
                print(Fore.GREEN + f"[+] Sistema operativo probable de {ip}: {result['os_guess']}")
                print(f"TTL: {result['ttl']} - Window Size: {result['window']}")

        elif choice == "0":
            print("Saliendo...")
            break
        
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()
