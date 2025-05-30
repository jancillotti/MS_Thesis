import ssl
import socket
import time

def run_client(port, cafile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True  
    context.load_verify_locations(cafile=cafile)
    start = time.time()
    with socket.create_connection(('localhost', port)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            ssock.sendall(b"This is my test TLS connection")
            print("[+] TLS version used:", ssock.version())
            print("[*] TLS established")
            print(ssock.recv(1024).decode())
    duration = (time.time() - start) * 1000
    print(f"[*] Handshake time: {duration} ms")
    return duration
