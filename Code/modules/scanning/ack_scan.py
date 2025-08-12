from scapy.all import IP, TCP, ICMP, sr1
import time

def ack_scan(ip, port, timeout=1):
    """
    Realiza un ACK Scan para detectar si un puerto está filtrado por un firewall.
    Devuelve 'Filtered', 'Unfiltered', 'Filtered (ICMP)' o 'Unknown'.
    """
    try:
        start_time = time.time()

        # Construimos paquete TCP con ACK flag
        pkt = IP(dst=ip) / TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=timeout, verbose=False)

        elapsed = round((time.time() - start_time) * 1000, 2)  # ms

        if resp is None:
            return f"Filtered (no response) [{elapsed} ms]"

        if resp.haslayer(TCP):
            tcp_flags = resp.getlayer(TCP).flags
            if tcp_flags == 0x4:  # RST
                return f"Unfiltered [{elapsed} ms]"
            else:
                return f"Unexpected TCP flags={tcp_flags} [{elapsed} ms]"

        if resp.haslayer(ICMP):
            icmp_type = resp.getlayer(ICMP).type
            icmp_code = resp.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                return f"Filtered (ICMP type={icmp_type} code={icmp_code}) [{elapsed} ms]"
            else:
                return f"ICMP response type={icmp_type} code={icmp_code} [{elapsed} ms]"

        return f"Unknown response [{elapsed} ms]"

    except Exception as e:
        return f"Error: {e}"


def run_ack_scan(ips, ports, timeout=1):
    """
    Ejecuta ACK Scan sobre múltiples IPs y puertos.
    """
    print("\n=== ACK Scan ===")
    for ip in ips:
        for port in ports:
            status = ack_scan(ip, port, timeout)
            print(f"[{ip}:{port}] -> {status}")


