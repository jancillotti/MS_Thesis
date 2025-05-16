# tls_server.py
import socket
import ssl
from generate_certs import generate_certs


def run_server(cert, key, port):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert, keyfile=key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(("localhost", 8443))
        sock.listen(5)
        print("Server listening on https://localhost:8443 ...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                print(f"Connection from {addr}")
                request = conn.recv(1024).decode()
                print("Received request:\n", request)

                # Simulate a basic HTTP response
                response_body = "Hello, world!"
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    f"{response_body}"
                )
                conn.sendall(response.encode())
                print("Sent HTTP response.")

