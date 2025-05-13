import ssl, socket

def run_server(cert, key, port):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    context.load_cert_chain(certfile=cert, keyfile=key)
    with socket.socket(socket.AF_INET) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(1)
        with context.wrap_socket(s, server_side=True) as ssock:
            print(f"[*] TLS server using cert: {cert}")
            conn, addr = ssock.accept()
            print("[*] Connection from", addr)
            conn.send(b"Hello over TLS!\n")
            conn.close()
            s.close()
