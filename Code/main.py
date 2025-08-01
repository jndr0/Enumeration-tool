import argparse
import sys
import os
from colorama import Fore, Style, init as colorama_init

# Importación de módulos por categoría
from modules.discovery import arp_ping, icmp_ping, tcp_ping
from modules.scanning import port_scan, syn_scan, tcp_connect, banner_grabbing
from modules.fingerprinting import os_detect, service_detection


def run_discovery(args):
    if args.discovery_method == 'arp':
        arp_ping.run(args.target)
    elif args.discovery_method == 'icmp':
        icmp_ping.run(args.target)
    elif args.discovery_method == 'tcp':
        tcp_ping.run(args.target)
    else:
        print("[-] Método de descubrimiento no válido.")

def run_scanning(args):
    if args.scan_type == 'port':
        start_port, end_port = map(int, args.port_range.split('-'))
        port_scan.run(args.target, start_port, end_port)
    elif args.scan_type == 'syn':
        syn_scan.run(args.target)
    elif args.scan_type == 'tcp-connect':
        tcp_connect.run(args.target)
    elif args.scan_type == 'banner':
        if args.port is None:
            print("[-] Debes especificar un puerto con --port para banner grabbing.")
        else:
            banner_grabbing.run(args.target, args.port)
    else:
        print("[-] Tipo de escaneo no válido.")

def run_fingerprinting(args):
    if args.fp_type == 'os':
        os_detect.run(args.target)
    else:
        print("[-] Tipo de fingerprinting no válido.")


def detect_services(ip, ports):
    print(f"\n[+] Detectando servicios en {ip}")
    for port in ports:
        result = service_detection.detect_service(ip, port)
        print(f"  [Port {port}] {result}")


def print_help_full():
    colorama_init()

    print(f"{Style.BRIGHT}{Fore.CYAN}Herramienta de enumeración y escaneo para redes internas.{Style.RESET_ALL}\n")

    print(f"{Fore.YELLOW}Modos disponibles:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}discover     {Style.RESET_ALL}- Descubrimiento de hosts en la red")
    print(f"  {Fore.GREEN}scan         {Style.RESET_ALL}- Escaneo de puertos y servicios")
    print(f"  {Fore.GREEN}fingerprint  {Style.RESET_ALL}- Fingerprinting del sistema objetivo\n")

    print(f"{Fore.YELLOW}Opciones generales:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--target            {Style.RESET_ALL}IP o red objetivo (obligatorio en todos los modos)")
    
    print(f"\n{Fore.YELLOW}Opciones para 'discover':{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--discovery-method  {Style.RESET_ALL}arp | icmp | tcp")

    print(f"\n{Fore.YELLOW}Opciones para 'scan':{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--scan-type         {Style.RESET_ALL}port | syn | tcp-connect | banner")
    print(f"  {Fore.CYAN}--port-range        {Style.RESET_ALL}Ejemplo: 1-1000 (por defecto: 1-1024)")
    print(f"  {Fore.CYAN}--port              {Style.RESET_ALL}Puerto específico (solo para banner grabbing)")

    print(f"\n{Fore.YELLOW}Opciones para 'fingerprint':{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--fp-type           {Style.RESET_ALL}os")

    print(f"\n{Fore.YELLOW}Ejemplos de uso:{Style.RESET_ALL}")
    print(f"  python main.py discover --target 192.168.1.0/24 --discovery-method arp")
    print(f"  python main.py scan --target 192.168.1.1 --scan-type port --port-range 1-1000")
    print(f"  python main.py fingerprint --target 192.168.1.1 --fp-type os\n")

    sys.exit(0)

def main():
    colorama_init()
    parser = argparse.ArgumentParser(description='Herramienta de enumeración y escaneo para redes internas.', add_help=False)

    subparsers = parser.add_subparsers(dest='mode')

    # Discover
    discover_parser = subparsers.add_parser('discover')
    discover_parser.add_argument('--target', required=True)
    discover_parser.add_argument('--discovery-method', choices=['arp', 'icmp', 'tcp'], required=True)

    # Scan
    scan_parser = subparsers.add_parser('scan')
    scan_parser.add_argument('--target', required=True)
    scan_parser.add_argument('--scan-type', choices=['port', 'syn', 'tcp-connect', 'banner'], required=True)
    scan_parser.add_argument('--port-range', default='1-1024')
    scan_parser.add_argument('--port', type=int)

    # Fingerprint
    fp_parser = subparsers.add_parser('fingerprint')
    fp_parser.add_argument('--target', required=True)
    fp_parser.add_argument('--fp-type', choices=['os'], required=True)

    # Si no hay argumentos o si solo se pide ayuda, mostrar ayuda personalizada
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help_full()

    args = parser.parse_args()

    if args.mode == 'discover':
        run_discovery(args)
    elif args.mode == 'scan':
        run_scanning(args)
    elif args.mode == 'fingerprint':
        run_fingerprinting(args)
    else:
        print_help_full()

if __name__ == '__main__':
    main()
