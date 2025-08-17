import argparse
from colorama import Fore, Style, init as colorama_init

colorama_init()

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

    # ----------------------------
    # Subparsers
    # ----------------------------
    subparsers = parser.add_subparsers(
        title="Modos disponibles",
        dest="mode",
        metavar="MODE",
        help="Modo de operación (usa 'MODE --help' para más detalles)"
    )
    subparsers.required = True  # ✅ Esto es clave en Python <3.7

    # DISCOVER
    discover_parser = subparsers.add_parser(
        "discover",
        help="Descubrimiento de hosts (ARP, ICMP, TCP)",
        description="Permite descubrir hosts activos en la red mediante diferentes métodos."
    )
    discover_parser.add_argument(
        "--method", required=True, choices=["arp", "icmp", "tcp"],
        help="Método de descubrimiento"
    )

    # SCAN
    scan_parser = subparsers.add_parser(
        "scan",
        help="Escaneo de puertos y servicios",
        description="Escanea los puertos de los hosts detectados con diferentes técnicas."
    )
    scan_parser.add_argument(
        "--scan-type", required=True,
        choices=["port", "syn", "tcp-connect", "banner", "ack"],
        help="Tipo de escaneo"
    )
    scan_parser.add_argument(
        "--port-range", default="1-1024",
        help="Rango de puertos para 'port scan' (por defecto: 1-1024, ej: 20-1000)"
    )
    scan_parser.add_argument(
        "--port", type=int,
        help="Puerto específico (obligatorio para 'banner' y 'ack')"
    )

    # FINGERPRINT
    fp_parser = subparsers.add_parser(
        "fingerprint",
        help="Fingerprinting de SO y servicios",
        description="Obtiene información detallada sobre el sistema operativo y servicios de un host."
    )
    fp_parser.add_argument(
        "--fp-type", required=True, choices=["os", "services"],
        help="Tipo de fingerprinting"
    )
    fp_parser.add_argument(
        "--ports", type=int, nargs="+",
        help="Lista de puertos (obligatorio si --fp-type services)"
    )

    args = parser.parse_args()

    # Validaciones extra
    if args.mode == "scan":
        if args.scan_type in ["banner", "ack"] and not args.port:
            parser.error(f"El tipo de escaneo '{args.scan_type}' requiere --port")

    if args.mode == "fingerprint":
        if args.fp_type == "services" and not args.ports:
            parser.error("El fingerprinting 'services' requiere --ports")

    # Ejecución simulada
    print(f"{Fore.CYAN}[+] Ejecutando modo {args.mode} con {args}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
