import argparse
from colorama import Fore, Style, init as colorama_init
from modules.discovery import arp_ping, icmp_ping, tcp_ping
from modules.scanning import port_scan, syn_scan, tcp_connect, banner_grabbing, ack_scan, udp_scan
from modules.fingerprinting import os_detect, service_detection

colorama_init(autoreset=True)

# ------------------- Estilo de salida -------------------
INFO    = Fore.CYAN + "[+]" + Style.RESET_ALL
OK      = Fore.GREEN + "[OK]" + Style.RESET_ALL
WARN    = Fore.YELLOW + "[!]" + Style.RESET_ALL
ERROR   = Fore.RED + "[-]" + Style.RESET_ALL
DEBUG   = Fore.MAGENTA + "[DEBUG]" + Style.RESET_ALL

# ------------------- Utils -------------------

def parse_ports(port_str):
    """Convierte una cadena de puertos en lista de enteros"""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

# ------------------- Modos -------------------

def run_discovery(method, targets):
    for ip in targets:
        print(f"{INFO} Descubrimiento en {ip}")
        if method == 'arp':
            arp_ping.run(ip)
        elif method == 'icmp':
            icmp_ping.run(ip)
        elif method == 'tcp':
            tcp_ping.run(ip)

def run_scanning(scan_type, targets, ports ):
    for ip in targets:
        print(f"{INFO} Escaneo en {ip}")
        if scan_type == 'port' and ports:
            port_scan.run(ip, min(ports), max(ports))
        elif scan_type == 'syn':
            syn_scan.run(ip)
        elif scan_type == 'tcp-connect':
            if not ports:
                raise ValueError(f"{ERROR} Para tcp-connect scan, -p/--ports es obligatorio")
            tcp_connect.run(ip, min(ports), max(ports))
        elif scan_type == 'banner' and ports:
            for p in ports:
                banner_grabbing.run(ip, p)
        elif scan_type == 'ack' and ports:
            for p in ports:
                ack_scan.run_ack_scan([ip], [p])
        elif scan_type == 'udp' and ports:
            udp_scan.run_udp_scan([ip], ports)

def run_fingerprinting(fp_type, targets, ports):
    for ip in targets:
        print(f"{INFO} Fingerprinting en {ip}")
        
        if fp_type == 'os':
            os_detect.run(ip)
        elif fp_type == 'services' and ports:
            service_detection.detect_services(ip, ports)
            

# ------------------- Main -------------------

def main():
    parser = argparse.ArgumentParser(description="Herramienta de enumeración y escaneo para redes internas.")
    parser.add_argument("--target", "-T", required=True, nargs="+", help="IP(s) o red(es) objetivo")

    # Modos
    parser.add_argument("-D", "--discover", choices=["arp", "icmp", "tcp"], help="Descubrimiento de hosts")
    parser.add_argument("-S", "--scan", choices=["port", "syn", "tcp-connect", "banner", "ack","udp"], help="Tipo de escaneo")
    parser.add_argument("-F", "--fingerprint", choices=["os", "services"], help="Fingerprinting de SO o servicios")

    # Puertos
    parser.add_argument("-p", "--ports", type=str, default="1-1024",
                        help="Lista o rango de puertos (ej: 80,443,1000-2000)")

    args = parser.parse_args()

    # Procesar puertos
    ports = parse_ports(args.ports) if args.ports else None

    # Validaciones y ejecución
    if args.discover:
        run_discovery(args.discover, args.target)
    elif args.scan:
        if args.scan in ["banner", "ack", "tcp-connect"] and not ports:
            parser.error(f"{ERROR} -p/--ports es obligatorio para este tipo de escaneo")
        run_scanning(args.scan, args.target, ports)
    elif args.fingerprint:
        if args.fingerprint == "services" and not ports:
            parser.error(f"{ERROR} -p/--ports es obligatorio para fingerprint de servicios")
        run_fingerprinting(args.fingerprint, args.target, ports)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
