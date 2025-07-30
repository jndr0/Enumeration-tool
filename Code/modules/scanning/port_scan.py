import socket

def run(target, start_port, end_port):
    print(f"[+] Escaneando puertos del {start_port} al {end_port} en {target}...\n")
    
    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Puerto abierto: {port}")
                open_ports.append(port)
            sock.close()
        except KeyboardInterrupt:
            print("\n[-] Interrumpido por el usuario.")
            break
        except Exception as e:
            print(f"[-] Error al escanear el puerto {port}: {e}")

    if not open_ports:
        print("[-] No se encontraron puertos abiertos.")
    else:
        print(f"\n[+] Total puertos abiertos: {len(open_ports)}")

