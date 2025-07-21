from colorama import Fore, Style, init
init(autoreset=True)

from discovery.arp_ping import arp_ping
from discovery.icmp_ping import icmp_ping
from discovery.tcp_ping import tcp_ping
from scanning.tcp_connect import tcp_connect_scan
from scanning.syn_scan import syn_scan
from scanning.banner_grabbing import grab_banner
from fingerprinting.os_detect import detect_os


def menu():
    print(Fore.CYAN + "\n=== Herramienta de Escaneo y Enumeración ===")
    print(Fore.YELLOW + "1." + Style.RESET_ALL + " Establecer IP/Red objetivo")
    print(Fore.YELLOW + "2." + Style.RESET_ALL + " ARP Ping")
    print(Fore.YELLOW + "3." + Style.RESET_ALL + " ICMP Ping")
    print(Fore.YELLOW + "4." + Style.RESET_ALL + " TCP Ping")
    print(Fore.YELLOW + "5." + Style.RESET_ALL + " TCP Connect Scan (Escaneo de puertos)")
    print(Fore.YELLOW + "6." + Style.RESET_ALL + " SYN Scan (Escaneo de puertos con Scapy)")
    print(Fore.YELLOW + "7." + Style.RESET_ALL + " Banner Grabbing")
    print(Fore.YELLOW + "8." + Style.RESET_ALL + " Detección de Sistema Operativo")
    print(Fore.RED + "0." + Style.RESET_ALL + " Salir")


def main():
    objetivo = None

    while True:
        menu()
        choice = input("Selecciona una opción: ")

        if choice == "1":
            objetivo = input("Introduce la IP o red objetivo (ej: 192.168.1.0/24 o 192.168.1.1): ")
            print(Fore.GREEN + f"[+] Objetivo establecido: {objetivo}")

        elif choice == "2":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            results = arp_ping(objetivo)
            print(Fore.GREEN + "\n[+] Dispositivos encontrados (ARP):")
            for d in results:
                print(f"- IP: {d['ip']} \t MAC: {d['mac']}")

        elif choice == "3":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            results = icmp_ping(objetivo)
            print(Fore.GREEN + "\n[+] Hosts activos (ICMP):")
            for ip in results:
                print(f"- IP: {ip}")

        elif choice == "4":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            port = int(input("Puerto a usar para TCP Ping (ej: 80): "))
            results = tcp_ping(objetivo, port)
            print(Fore.GREEN + "\n[+] Hosts activos (TCP Ping):")
            for ip in results:
                print(f"- IP: {ip}")

        elif choice == "5":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            start_port = int(input("Puerto inicial: "))
            end_port = int(input("Puerto final: "))
            results = tcp_connect_scan(objetivo, start_port, end_port)
            print(Fore.GREEN + f"\n[+] Puertos abiertos en {objetivo}:")
            for port in results:
                print(f"- Puerto {port} abierto")

        elif choice == "6":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            start_port = int(input("Puerto inicial: "))
            end_port = int(input("Puerto final: "))
            results = syn_scan(objetivo, start_port, end_port)
            print(Fore.GREEN + f"[+] Puertos abiertos (SYN Scan) en {objetivo}:")
            for port in results:
                print(f"- Puerto {port} abierto")

        elif choice == "7":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            port = int(input("Puerto (ej: 80, 21, 22): "))
            banner = grab_banner(objetivo, port)
            print(Fore.GREEN + f"[+] Banner obtenido:")
            print(banner if banner else "No se recibió respuesta.")

        elif choice == "8":
            if not objetivo:
                print(Fore.RED + "Establece primero el objetivo con la opción 1.")
                continue
            result = detect_os(objetivo)
            if "error" in result:
                print(Fore.RED + result["error"])
            else:
                print(Fore.GREEN + f"[+] Sistema operativo probable de {objetivo}: {result['os_guess']}")
                print(f"TTL: {result['ttl']} - Window Size: {result['window']}")

        elif choice == "0":
            print("Saliendo...")
            break

        else:
            print(Fore.RED + "Opción no válida.")


if __name__ == "__main__":
    main()
