import argparse
import sys
from colorama import Fore, Style, init as colorama_init

# Importación de módulos (ajusta las rutas según tu estructura)
from modules.discovery import arp_ping, icmp_ping, tcp_ping
from modules.scanning import port_scan, syn_scan, tcp_connect, banner_grabbing, ack_scan
from modules.fingerprinting import os_detect, service_detection

colorama_init()

def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def run_discovery(method, targets):
    for ip in targets:
        print(f"{Fore.CYAN}[+] Descubrimiento en {ip}{Style.RESET_ALL}")
        if method == 'arp':
            arp_ping.run(ip)
        elif method == 'icmp':
            icmp_ping.run(ip)
        elif method == 'tcp':
            tcp_ping.run(ip)

def run_scanning(scan_type, targets, ports):
    for ip in targets:
        print(f"{Fore.CYAN}[+] Escaneo en {ip}{Style.RESET_ALL}")
        if scan_type == 'port' and ports:
            port_scan.run(ip, min(ports), max(ports))
        elif scan_type == 'syn':
            syn_scan.run(ip)
        elif scan_type == 'tcp-connect':
            tcp_connect.run(ip)
        elif scan_type == 'banner' and ports:
            for p in ports:
                banner_grabbing.run(ip, p)
        elif scan_type == 'ack' and ports:
            for p in ports:
                ack_scan.run_ack_scan([ip], [p])

def run_fingerprinting(fp_type, targets, ports):
    for ip in targets:
        print(f"{Fore.CYAN}[+] Fingerprinting en {ip}{Style.RESET_ALL}")
        if fp_type == 'os':
            os_detect.run(ip)
        elif fp_type == 'services' and ports:
            service_detection.detect_services(ip, ports)

def main():
    parser = argparse.ArgumentParser(description="Herramienta de enumeración y escaneo para redes internas.")
    parser.add_argument("--target", "-T", required=True, nargs="+", help="IP(s) o red(es) objetivo")

    # Modo Discover
    parser.add_argument("-D", "--discover", choices=["arp", "icmp", "tcp"], help="Descubrimiento de hosts")

    # Modo Scan
    parser.add_argument("-S", "--scan", choices=["port", "syn", "tcp-connect", "banner", "ack"], help="Tipo de escaneo")

    # Modo Fingerprinting
    parser.add_argument("-F", "--fingerprint", choices=["os", "services"], help="Fingerprinting de SO o servicios")

    # Puertos 
    parser.add_argument("-p", "--ports", type=str, help="Lista o rango de puertos (ej: 80,443,1000-2000)")

    args = parser.parse_args()

    # Procesar puertos
    ports = parse_ports(args.ports) if args.ports else None

    # Validaciones condicionales
    if args.discover:
        run_discovery(args.discover, args.target)
    elif args.scan:
        if args.scan in ["banner", "ack"] and not ports:
            parser.error("-p/--ports es obligatorio para los modos 'banner' o 'ack'")
        run_scanning(args.scan, args.target, ports)
    elif args.fingerprint:
        if args.fingerprint == "services" and not ports:
            parser.error("-p/--ports es obligatorio para fingerprint de servicios")
        run_fingerprinting(args.fingerprint, args.target, ports)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
