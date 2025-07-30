import argparse
import sys
import os

# Asegurar que se puede importar el paquete modules correctamente
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

# Importación de módulos por categoría
from modules.discovery import arp_ping, icmp_ping, tcp_ping
from modules.scanning import port_scan, syn_scan, tcp_connect, banner_grabbing
from modules.fingerprinting import os_detect

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
        banner_grabbing.run(args.target, args.port)
    else:
        print("[-] Tipo de escaneo no válido.")

def run_fingerprinting(args):
    if args.fp_type == 'os':
        os_detect.run(args.target)
    else:
        print("[-] Tipo de fingerprinting no válido.")

def main():
    parser = argparse.ArgumentParser(description='Herramienta de enumeración y escaneo para redes internas.')

    subparsers = parser.add_subparsers(dest='mode', help='Modo de operación')

    # -------------------------
    # Descubrimiento
    # -------------------------
    discovery_parser = subparsers.add_parser('discover', help='Modo descubrimiento de hosts')
    discovery_parser.add_argument('--target', required=True, help='IP o red objetivo')
    discovery_parser.add_argument('--discovery-method', choices=['arp', 'icmp', 'tcp'], required=True)

    # -------------------------
    # Escaneo
    # -------------------------
    scan_parser = subparsers.add_parser('scan', help='Modo escaneo de puertos y servicios')
    scan_parser.add_argument('--target', required=True, help='IP objetivo')
    scan_parser.add_argument('--scan-type', choices=['port', 'syn', 'tcp-connect', 'banner'], required=True)
    scan_parser.add_argument('--port-range', default='1-1024', help='Rango de puertos (ej: 1-1000)')
    scan_parser.add_argument('--port', type=int, help='Puerto específico (para banner grabbing)')

    # -------------------------
    # Fingerprinting
    # -------------------------
    fp_parser = subparsers.add_parser('fingerprint', help='Modo fingerprinting')
    fp_parser.add_argument('--target', required=True, help='IP objetivo')
    fp_parser.add_argument('--fp-type', choices=['os'], required=True)

    args = parser.parse_args()

    if args.mode == 'discover':
        run_discovery(args)
    elif args.mode == 'scan':
        run_scanning(args)
    elif args.mode == 'fingerprint':
        run_fingerprinting(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
