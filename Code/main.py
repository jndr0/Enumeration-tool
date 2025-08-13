import argparse
import sys
from colorama import Fore, Style, init as colorama_init

# Importación de módulos (ajusta las rutas según tu estructura)
from modules.discovery import arp_ping, icmp_ping, tcp_ping
from modules.scanning import port_scan, syn_scan, tcp_connect, banner_grabbing, ack_scan
from modules.fingerprinting import os_detect, service_detection

colorama_init()

def run_discovery(method, targets):
    for ip in targets:
        print(f"{Fore.CYAN}[+] Descubrimiento en {ip}{Style.RESET_ALL}")
        if method == 'arp':
            arp_ping.run(ip)
        elif method == 'icmp':
            icmp_ping.run(ip)
        elif method == 'tcp':
            tcp_ping.run(ip)

def run_scanning(scan_type, targets, port_range, port):
    for ip in targets:
        print(f"{Fore.CYAN}[+] Escaneo en {ip}{Style.RESET_ALL}")
        start_port, end_port = map(int, port_range.split('-'))
        if scan_type == 'port':
            port_scan.run(ip, start_port, end_port)
        elif scan_type == 'syn':
            syn_scan.run(ip)
        elif scan_type == 'tcp-connect':
            tcp_connect.run(ip)
        elif scan_type == 'banner' and port:
            banner_grabbing.run(ip, port)
        elif scan_type == 'ack' and port:
            ack_scan.run_ack_scan([ip], [port])

def run_fingerprinting(fp_type, targets, ports):
    for ip in targets:
        print(f"{Fore.CYAN}[+] Fingerprinting en {ip}{Style.RESET_ALL}")
        if fp_type == 'os':
            os_detect.run(ip)
        elif fp_type == 'services' and ports:
            service_detection.detect_services(ip, ports)

def main():
    parser = argparse.ArgumentParser(description="Herramienta de enumeración y escaneo para redes internas.")
    parser.add_argument("--target", required=True, nargs="+", help="IP(s) o red(es) objetivo")
    parser.add_argument("--mode", required=True, choices=["discover", "scan", "fingerprint"], help="Modo de operación")
    
    # Opciones comunes
    parser.add_argument("--method", choices=["arp", "icmp", "tcp"], help="Método para 'discover'")
    parser.add_argument("--scan-type", choices=["port", "syn", "tcp-connect", "banner", "ack"], help="Tipo de escaneo")
    parser.add_argument("--port-range", default="1-1024", help="Rango de puertos para 'port scan' (por defecto: 1-1024)")
    parser.add_argument("--port", type=int, help="Puerto específico (para banner o ack)")
    parser.add_argument("--fp-type", choices=["os", "services"], help="Tipo de fingerprinting")
    parser.add_argument("--ports", type=int, nargs="+", help="Lista de puertos para fingerprinting de servicios")

    args = parser.parse_args()

    # Ejecución unificada
    if args.mode == "discover" and args.method:
        run_discovery(args.method, args.target)
    elif args.mode == "scan" and args.scan_type:
        run_scanning(args.scan_type, args.target, args.port_range, args.port)
    elif args.mode == "fingerprint" and args.fp_type:
        run_fingerprinting(args.fp_type, args.target, args.ports)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
