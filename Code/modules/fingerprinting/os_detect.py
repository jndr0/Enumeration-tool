from scapy.all import IP, TCP, sr1

def detect_os(ip):
    pkt = IP(dst=ip)/TCP(dport=80, flags='S')
    resp = sr1(pkt, timeout=2, verbose=0)

    if resp:
        ttl = resp.ttl
        window = resp[TCP].window
        if ttl <= 64:
            os = "Linux/Unix (probable)"
        elif ttl <= 128:
            os = "Windows (probable)"
        else:
            os = "Desconocido"

        return {"ip": ip, "ttl": ttl, "window": window, "os_guess": os}
    else:
        return {"ip": ip, "error": "Sin respuesta"}
