# tls_client.py
from urllib.parse import urlparse
import socket
import ssl
import sys
import time

def run_client(port, url, cafile):
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 443
    path = parsed.path or "/"

    context = ssl.create_default_context()

    # Force certificate verification
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True  # optional, but recommended
    context.load_verify_locations(cafile=cafile)
    start = time.time()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(f"Connected to {host}:{port}")

            # Simulate sending an HTTP GET request
            http_request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            ssock.sendall(http_request.encode())

            # Read HTTP response from server
            response = b""
            while True:
                data = ssock.recv(1024)
                if not data:
                    break
                response += data

            print("Received response:\n")
            print(response.decode())
    duration = (time.time() - start) * 1000
    print(f"[*] Connection time: {duration} ms")
    return duration


