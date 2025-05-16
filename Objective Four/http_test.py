import subprocess
import time
import os
from http_client import run_client
from multiprocessing import Process
from http_server import run_server

def run_test(name, cert, key, port):
    print(f"\n[*] Running test: {name}")
    
    # Start tcpdump
    tcpdump_file = "handshake.pcap"
    tcpdump = subprocess.Popen([
        "sudo", "timeout", "10", "tcpdump", "-i", "lo", "port", str(port), "-w", tcpdump_file
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Start server
    server_proc = Process(target=run_server, args=(cert, key, port))
    server_proc.start()
    time.sleep(2)

    # Run client
    try:
        handshake_time = run_client(port, 'https://localhost:8443/hello', cert)
    except Exception as e:
        print(f"[!] Client failed: {e}")
        handshake_time = "Failed"
    
    print(handshake_time)
    server_proc.join(timeout=5)
    server_proc.terminate()

    # Get cert size
    cert_size = os.path.getsize(cert)
    cert_size_kb = f"{cert_size / 1024:.1f} KB"

    return (name, str(handshake_time), cert_size_kb)


