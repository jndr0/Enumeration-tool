import argparse
import sys
from colorama import Fore, Style, init as colorama_init

# Importación de módulos por categoría
from modules.discovery import arp_ping, icmp_ping, tcp_ping
from modules.scanning import port_scan, syn_scan, tcp_connect, banner_grabbing, ack_scan
from modules.fingerprinting import os_detect, service_detection

def run_discovery(args):
    for ip in args.target:
        print(f"{Fore.CYAN}[+] Descubrimiento en {ip}{Style.RESET_ALL}")
        if args.discovery_method == 'arp':
            arp_ping.run(ip)
        elif args.discovery_method == 'icmp':
            icmp_ping.run(ip)
        elif args.discovery_method == 'tcp':
            tcp_ping.run(ip)
        else:
            print(f"{Fore.RED}[-] Método de descubrimiento no válido.{Style.RESET_ALL}")

def run_scanning(args):
    for ip in args.target:
        print(f"{Fore.CYAN}[+] Escaneo en {ip}{Style.RESET_ALL}")
        if args.scan_type == 'port':
            start_port, end_port = map(int, args.port_range.split('-'))
            port_scan.run(ip, start_port, end_port)
        elif args.scan_type == 'syn':
            syn_scan.run(ip)
        elif args.scan_type == 'tcp-connect':
            tcp_connect.run(ip)
        elif args.scan_type == 'banner':
            if args.port is None:
                print(f"{Fore.RED}[-] Debes especificar un puerto con --port para banner grabbing.{Style.RESET_ALL}")
            else:
                banner_grabbing.run(ip, args.port)
        elif args.scan_type == 'ack':
            if args.port is None:
                print(f"{Fore.RED}[-] Debes especificar un puerto con --port para ACK scan.{Style.RESET_ALL}")
            else:
                ack_scan.run_ack_scan([ip], [args.port])
        else:
            print(f"{Fore.RED}[-] Tipo de escaneo no válido.{Style.RESET_ALL}")

def run_fingerprinting(args):
    for ip in args.target:
        print(f"{Fore.CYAN}[+] Fingerprinting en {ip}{Style.RESET_ALL}")
        if args.fp_type == 'os':
            os_detect.run(ip)
        elif args.fp_type == 'services':
            if args.ports is None:
                print(f"{Fore.RED}[-] Debes especificar puertos con --ports para detección de servicios.{Style.RESET_ALL}")
            else:
                service_detection.detect_services(ip, args.ports)
        else:
            print(f"{Fore.RED}[-] Tipo de fingerprinting no válido.{Style.RESET_ALL}")

def print_help_full():
    colorama_init()
    print(f"{Style.BRIGHT}{Fore.CYAN}Herramienta de enumeración y escaneo para redes internas.{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}Modos disponibles:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}discover     {Style.RESET_ALL}- Descubrimiento de hosts")
    print(f"  {Fore.GREEN}scan         {Style.RESET_ALL}- Escaneo de puertos y servicios")
    print(f"  {Fore.GREEN}fingerprint  {Style.RESET_ALL}- Fingerprinting del objetivo\n")
    print(f"{Fore.YELLOW}Opciones generales:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--target            {Style.RESET_ALL}IPs objetivo (uno o varios separados por espacio)")
    print(f"\n{Fore.YELLOW}Opciones para 'discover':{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--discovery-method  {Style.RESET_ALL}arp | icmp | tcp")
    print(f"\n{Fore.YELLOW}Opciones para 'scan':{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--scan-type         {Style.RESET_ALL}port | syn | tcp-connect | banner")
    print(f"  {Fore.CYAN}--port-range        {Style.RESET_ALL}Ej: 1-1000 (por defecto: 1-1024)")
    print(f"  {Fore.CYAN}--port              {Style.RESET_ALL}Puerto específico (solo para banner grabbing)")
    print(f"\n{Fore.YELLOW}Opciones para 'fingerprint':{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}--fp-type           {Style.RESET_ALL}os | services")
    print(f"  {Fore.CYAN}--ports             {Style.RESET_ALL}Lista de puertos (ej: --ports 22 80 443)")
    print(f"\n{Fore.YELLOW}Ejemplos de uso:{Style.RESET_ALL}")
    print(f"  python main.py discover --target 192.168.1.1 192.168.1.2 --discovery-method arp")
    print(f"  python main.py scan --target 192.168.1.1 --scan-type port --port-range 1-1000")
    print(f"  python main.py fingerprint --target 192.168.1.1 192.168.1.5 --fp-type services --ports 22 80\n")

def main():
    colorama_init()
    parser = argparse.ArgumentParser(description='Herramienta de enumeración y escaneo para redes internas.', add_help=False)

    subparsers = parser.add_subparsers(dest='mode')

    # Discover
    discover_parser = subparsers.add_parser('discover')
    discover_parser.add_argument('--target', required=True, nargs='+')
    discover_parser.add_argument('--discovery-method', choices=['arp', 'icmp', 'tcp'], required=True)

    # Scan
    scan_parser = subparsers.add_parser('scan')
    scan_parser.add_argument('--target', required=True, nargs='+')
    scan_parser.add_argument('--scan-type', choices=['port', 'syn', 'tcp-connect', 'banner', 'ack'], required=True)
    scan_parser.add_argument('--port-range', default='1-1024')
    scan_parser.add_argument('--port', type=int)

    # Fingerprint
    fp_parser = subparsers.add_parser('fingerprint')
    fp_parser.add_argument('--target', required=True, nargs='+')
    fp_parser.add_argument('--fp-type', choices=['os', 'services'], required=True)
    fp_parser.add_argument('--ports', type=int, nargs='+', help="Lista de puertos (ej: --ports 22 80 443)")

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help_full()
        return

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
