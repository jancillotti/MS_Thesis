import subprocess
import os

CERT_DIR = "certs"

def generate_certs():
    os.makedirs(CERT_DIR, exist_ok=True)
    rsa_key = f"{CERT_DIR}/rsa.key"
    rsa_crt = f"{CERT_DIR}/rsa.crt"
    sphincs_key = f"{CERT_DIR}/sphincssha2128fsimple.key"
    sphincs_crt = f"{CERT_DIR}/sphincssha2128fsimple.crt"
    ml_dsa_key = f"{CERT_DIR}/mldsa44.key"
    ml_dsa_crt = f"{CERT_DIR}/mldsa44.crt"
    falcon_key = f"{CERT_DIR}/falcon512.key"
    falcon_cert = f"{CERT_DIR}/falcon512.crt"
    rsa_sphincs_key = f"{CERT_DIR}/rsa3072_sphincssha2128fsimple.key"
    rsa_sphincs_crt = f"{CERT_DIR}/rsa3072_sphincssha2128fsimple.crt"
    rsa_mldsa_key = f"{CERT_DIR}/mldsa44_rsa2048.key"
    rsa_mldsa_crt = f"{CERT_DIR}/mldsa44_rsa2048.crt"
    rsa_falcon_key = f"{CERT_DIR}/rsa3072_falcon512.key"
    rsa_falcon_crt = f"{CERT_DIR}/rsa3072_falcon512.crt"


    print("[*] Generating SPHINCS+ certificate...")
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-newkey", "sphincssha2128fsimple",
        "-keyout", sphincs_key, "-out", sphincs_crt,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
        "-config", "/etc/ssl/openssl.cnf"
    ], check=True)

    print("[*] Generating RSA certificate...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:3072",
        "-keyout", rsa_key, "-out", rsa_crt,
        "-days", "365", "-nodes", "-subj", "/CN=localhost"
    ], check=True)

    print("[*] Generating RSA & SPHINCS certificate...")

    subprocess.run([
        "openssl", "req", "-x509", "-new", "-newkey", "rsa3072_sphincssha2128fsimple",
        "-keyout", rsa_sphincs_key, "-out", rsa_sphincs_crt,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
        "-config", "/etc/ssl/openssl.cnf"
    ], check=True)

    subprocess.run([
        "openssl", "req", "-x509", "-new", "-newkey", "mldsa44",
        "-keyout", ml_dsa_key, "-out", ml_dsa_crt,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
        "-config", "/etc/ssl/openssl.cnf"
    ], check=True)

    subprocess.run([
        "openssl", "req", "-x509", "-new", "-newkey", "mldsa44_rsa2048",
        "-keyout", rsa_mldsa_key, "-out", rsa_mldsa_crt,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
        "-config", "/etc/ssl/openssl.cnf"
    ], check=True)

    subprocess.run([
        "openssl", "req", "-x509", "-new", "-newkey", "falcon512",
        "-keyout", falcon_key, "-out", falcon_cert,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
        "-config", "/etc/ssl/openssl.cnf"
    ], check=True)

    subprocess.run([
        "openssl", "req", "-x509", "-new", "-newkey", "rsa3072_falcon512",
        "-keyout", rsa_falcon_key, "-out", rsa_falcon_crt,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
        "-config", "/etc/ssl/openssl.cnf"
    ], check=True)

    return {
        "RSA 2048": (rsa_crt, rsa_key),
        "ML-DSA ": (ml_dsa_crt, ml_dsa_key),
        "Faclon ": (falcon_cert, falcon_key),
        "SPHINCS+ sha2-128f-simple": (sphincs_crt, sphincs_key),
        "RSA & SPHINCS": (rsa_sphincs_crt, rsa_sphincs_key),
        "RSA & MLDSA ": (rsa_mldsa_crt, rsa_mldsa_key),
        "RSA & Falcon ": (rsa_falcon_crt, rsa_falcon_key)



    }
