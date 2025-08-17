import argparse
from colorama import Fore, Style, init as colorama_init

colorama_init()

def main():
    parser = argparse.ArgumentParser(
        description=(
            f"{Fore.CYAN}Herramienta de enumeración y escaneo para redes internas{Style.RESET_ALL}\n\n"
            f"{Fore.YELLOW}Ejemplos de uso:{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}Descubrimiento ARP:{Style.RESET_ALL}\n"
            "    python tool.py --target 192.168.1.0/24 discover --method arp\n\n"
            f"  {Fore.GREEN}Escaneo SYN en un host:{Style.RESET_ALL}\n"
            "    python tool.py --target 192.168.1.10 scan --scan-type syn\n\n"
            f"  {Fore.GREEN}Banner grabbing en un puerto:{Style.RESET_ALL}\n"
            "    python tool.py --target 192.168.1.10 scan --scan-type banner --port 80\n\n"
            f"  {Fore.GREEN}Fingerprinting de servicios:{Style.RESET_ALL}\n"
            "    python tool.py --target 192.168.1.10 fingerprint --fp-type services --ports 21 22 80\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--target", required=True, nargs="+",
        help=f"{Fore.YELLOW}IP(s) o red(es) objetivo{Style.RESET_ALL} (ej: 192.168.1.1 o 192.168.1.0/24)"
    )

    subparsers = parser.add_subparsers(
        title=f"{Fore.CYAN}Modos disponibles{Style.RESET_ALL}",
        dest="mode",
        metavar="MODE",
        help="Selecciona un modo (usa 'MODE --help' para más detalles)"
    )
    subparsers.required = True

    # DISCOVER
    discover_parser = subparsers.add_parser(
        "discover",
        help=f"{Fore.GREEN}Descubrimiento de hosts (ARP, ICMP, TCP){Style.RESET_ALL}",
        description=f"{Fore.CYAN}Permite descubrir hosts activos en la red mediante diferentes métodos.{Style.RESET_ALL}"
    )
    discover_parser.add_argument(
        "--method", required=True, choices=["arp", "icmp", "tcp"],
        help=f"{Fore.YELLOW}Método de descubrimiento{Style.RESET_ALL}"
    )

    # SCAN
    scan_parser = subparsers.add_parser(
        "scan",
        help=f"{Fore.GREEN}Escaneo de puertos y servicios{Style.RESET_ALL}",
        description=f"{Fore.CYAN}Escanea los puertos de los hosts detectados con diferentes técnicas.{Style.RESET_ALL}"
    )
    scan_parser.add_argument(
        "--scan-type", required=True,
        choices=["port", "syn", "tcp-connect", "banner", "ack"],
        help=f"{Fore.YELLOW}Tipo de escaneo{Style.RESET_ALL}"
    )
    scan_parser.add_argument(
        "--port-range", default="1-1024",
        help=f"{Fore.YELLOW}Rango de puertos{Style.RESET_ALL} para 'port scan' (ej: 20-1000, por defecto 1-1024)"
    )
    scan_parser.add_argument(
        "--port", type=int,
        help=f"{Fore.YELLOW}Puerto específico{Style.RESET_ALL} (obligatorio para 'banner' y 'ack')"
    )

    # FINGERPRINT
    fp_parser = subparsers.add_parser(
        "fingerprint",
        help=f"{Fore.GREEN}Fingerprinting de SO y servicios{Style.RESET_ALL}",
        description=f"{Fore.CYAN}Obtiene información detallada sobre el sistema operativo y servicios de un host.{Style.RESET_ALL}"
    )
    fp_parser.add_argument(
        "--fp-type", required=True, choices=["os", "services"],
        help=f"{Fore.YELLOW}Tipo de fingerprinting{Style.RESET_ALL}"
    )
    fp_parser.add_argument(
        "--ports", type=int, nargs="+",
        help=f"{Fore.YELLOW}Lista de puertos{Style.RESET_ALL} (obligatorio si --fp-type services)"
    )

    args = parser.parse_args()

    print(f"{Fore.CYAN}[+] Ejecutando modo {args.mode}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
