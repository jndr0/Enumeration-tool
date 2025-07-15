import socket

def grab_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: "+ip.encode()+b"\r\n\r\n")
            banner = s.recv(1024)
            return banner.decode(errors="ignore")
    except Exception as e:
        return None
