import argparse
import sys
from colorama import Fore, Style, init as colorama_init


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
    parser = argparse.ArgumentParser(
        description=(
            "Herramienta de enumeración y escaneo para redes internas.\n\n"
            "Ejemplos de uso:\n"
            "  Descubrimiento ARP:\n"
            "    python tool.py --target 192.168.1.0/24 discover --method arp\n\n"
            "  Escaneo SYN en un host:\n"
            "    python tool.py --target 192.168.1.10 scan --scan-type syn\n\n"
            "  Banner grabbing en un puerto:\n"
            "    python tool.py --target 192.168.1.10 scan --scan-type banner --port 80\n\n"
            "  Fingerprinting de servicios:\n"
            "    python tool.py --target 192.168.1.10 fingerprint --fp-type services --ports 21 22 80\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--target", required=True, nargs="+",
        help="IP(s) o red(es) objetivo (ej: 192.168.1.1 o 192.168.1.0/24)"
    )

    subparsers = parser.add_subparsers(dest="mode", required=True, help="Modo de operación")

    # ============================
    # Subparser: DISCOVER
    # ============================
    discover_parser = subparsers.add_parser(
        "discover",
        help="Modo descubrimiento de hosts",
        description="Permite descubrir hosts activos en la red mediante diferentes métodos."
    )
    discover_parser.add_argument(
        "--method", required=True, choices=["arp", "icmp", "tcp"],
        help="Método de descubrimiento:\n"
             "  arp   → Requiere estar en la misma LAN (ARP ping)\n"
             "  icmp  → Envío de paquetes ICMP echo-request\n"
             "  tcp   → Intento de conexión TCP a puertos comunes"
    )

    # ============================
    # Subparser: SCAN
    # ============================
    scan_parser = subparsers.add_parser(
        "scan",
        help="Modo escaneo de puertos/servicios",
        description="Escanea los puertos de los hosts detectados con diferentes técnicas."
    )
    scan_parser.add_argument(
        "--scan-type", required=True,
        choices=["port", "syn", "tcp-connect", "banner", "ack"],
        help="Tipo de escaneo:\n"
             "  port         → Escaneo de rango de puertos (--port-range)\n"
             "  syn          → Escaneo SYN stealth\n"
             "  tcp-connect  → Escaneo TCP completo\n"
             "  banner       → Obtiene banners de un servicio (--port requerido)\n"
             "  ack          → Escaneo ACK para detección de firewalls (--port requerido)"
    )
    scan_parser.add_argument(
        "--port-range", default="1-1024",
        help="Rango de puertos para 'port scan' (por defecto: 1-1024, ej: 20-1000)"
    )
    scan_parser.add_argument(
        "--port", type=int,
        help="Puerto específico (obligatorio para 'banner' y 'ack')"
    )

    # ============================
    # Subparser: FINGERPRINT
    # ============================
    fp_parser = subparsers.add_parser(
        "fingerprint",
        help="Modo fingerprinting (OS y servicios)",
        description="Obtiene información detallada sobre el sistema operativo y servicios de un host."
    )
    fp_parser.add_argument(
        "--fp-type", required=True, choices=["os", "services"],
        help="Tipo de fingerprinting:\n"
             "  os       → Detección del sistema operativo\n"
             "  services → Detección de servicios (requiere --ports)"
    )
    fp_parser.add_argument(
        "--ports", type=int, nargs="+",
        help="Lista de puertos (obligatorio si --fp-type services)"
    )

    args = parser.parse_args()

    # ============================
    # Validaciones adicionales
    # ============================
    if args.mode == "scan":
        if args.scan_type in ["banner", "ack"] and not args.port:
            parser.error(f"El tipo de escaneo '{args.scan_type}' requiere --port")

    if args.mode == "fingerprint":
        if args.fp_type == "services" and not args.ports:
            parser.error("El fingerprinting 'services' requiere --ports")

    # ============================
    # Ejecución unificada
    # ============================
    if args.mode == "discover":
        run_discovery(args.method, args.target)
    elif args.mode == "scan":
        run_scanning(args.scan_type, args.target, args.port_range, args.port)
    elif args.mode == "fingerprint":
        run_fingerprinting(args.fp_type, args.target, args.ports)
