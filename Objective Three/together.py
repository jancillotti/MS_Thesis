import hashlib
import ecdsa
import os
import struct
import time
import pyspx.sha2_128s as sphincs_sha256s
import pyspx.sha2_128f as sphincs_sha256f
import pyspx.shake_128f


def ripemd160_sha256(data):
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()

def serialize_transaction(inputs, outputs, address_hex=True):
    tx_version = struct.pack("<L", 1)
    tx_in_count = struct.pack("<B", len(inputs))
    tx_inputs_serialized = b""
    for tx_id, index in inputs:
        tx_id_bytes = bytes.fromhex(tx_id)[::-1]
        tx_index = struct.pack("<L", index)
        script_sig = b""
        script_sig_length = struct.pack("<B", len(script_sig))
        sequence = b"\xff\xff\xff\xff"
        tx_inputs_serialized += tx_id_bytes + tx_index + script_sig_length + script_sig + sequence

    tx_out_count = struct.pack("<B", len(outputs))
    tx_outputs_serialized = b""
    for address, amount in outputs:
        if address_hex:
            address_bytes = bytes.fromhex(address)
        else:
            address_bytes = address
        satoshis = struct.pack("<Q", int(amount * 100_000_000))
        script_pubkey = b"\x76\xa9" + struct.pack("<B", 20) + address_bytes + b"\x88\xac"
        script_pubkey_length = struct.pack("<B", len(script_pubkey))
        tx_outputs_serialized += satoshis + script_pubkey_length + script_pubkey

    tx_locktime = struct.pack("<L", 0)
    return tx_version + tx_in_count + tx_inputs_serialized + tx_out_count + tx_outputs_serialized + tx_locktime

def run_ecdsa():
    timings = {}
    sizes = {}

    start = time.perf_counter()
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(private_key.to_string())
    sizes["Public Key"] = len(public_key.to_string())

    start = time.perf_counter()
    mock_address = ripemd160_sha256(public_key.to_string()).hex()
    timings["Address Generation"] = time.perf_counter() - start

    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(mock_address, 0.5)]
    timings["TX Setup"] = time.perf_counter() - start

    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    start = time.perf_counter()
    signature = private_key.sign(tx_hash)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(signature)

    start = time.perf_counter()
    valid = public_key.verify(signature, tx_hash)
    timings["Verification"] = time.perf_counter() - start

    return timings, sizes, valid

def run_sphincs_s():
    timings = {}
    sizes = {}

    start = time.perf_counter()
    seed = os.urandom(sphincs_sha256s.crypto_sign_SEEDBYTES)
    timings["Seed Generation"] = time.perf_counter() - start
    sizes["Seed"] = len(seed)

    start = time.perf_counter()
    public_key, private_key = sphincs_sha256s.generate_keypair(seed)
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(private_key)
    sizes["Public Key"] = len(public_key)

    start = time.perf_counter()
    mock_address = ripemd160_sha256(public_key).hex()
    timings["Address Generation"] = time.perf_counter() - start

    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(mock_address, 0.5)]
    timings["TX Setup"] = time.perf_counter() - start

    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    start = time.perf_counter()
    signature = sphincs_sha256s.sign(tx_hash, private_key)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(signature)

    start = time.perf_counter()
    valid = sphincs_sha256s.verify(tx_hash, signature, public_key)
    timings["Verification"] = time.perf_counter() - start

    return timings, sizes, valid

def run_sphincs_sha256f():
    timings = {}
    sizes = {}

    start = time.perf_counter()
    seed = os.urandom(sphincs_sha256f.crypto_sign_SEEDBYTES)
    timings["Seed Generation"] = time.perf_counter() - start
    sizes["Seed"] = len(seed)

    start = time.perf_counter()
    public_key, private_key = sphincs_sha256f.generate_keypair(seed)
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(private_key)
    sizes["Public Key"] = len(public_key)

    start = time.perf_counter()
    mock_address = ripemd160_sha256(public_key).hex()
    timings["Address Generation"] = time.perf_counter() - start

    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(mock_address, 0.5)]
    timings["TX Setup"] = time.perf_counter() - start

    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    start = time.perf_counter()
    signature = sphincs_sha256f.sign(tx_hash, private_key)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(signature)

    start = time.perf_counter()
    valid = sphincs_sha256f.verify(tx_hash, signature, public_key)
    timings["Verification"] = time.perf_counter() - start

    return timings, sizes, valid

def print_comparison_table(title, *data_label_pairs):
    print(f"\n{title}")
    print("-" * len(title))
    
    # Extract keys and headers
    all_keys = set()
    labels = []
    for data, label in data_label_pairs:
        labels.append(label)
        all_keys |= set(data.keys())
    keys = sorted(all_keys)

    # Print header
    col_width = 20
    print(f"{'Step':<30}" + "".join(f"{label:^{col_width}}" for label in labels))
    print("-" * (30 + col_width * len(labels)))

    # Print data rows
    for key in keys:
        row = f"{key:<30}"
        for data, _ in data_label_pairs:
            val = data.get(key, "")
            if isinstance(val, float):
                row += f"{val:.6f}s".center(col_width)
            elif isinstance(val, int):
                row += f"{val} B".center(col_width)
            else:
                row += str(val).center(col_width)
        print(row)


def run_hybrid_signature():
    timings = {}
    sizes = {}

    # ECDSA Key Pair Generation
    start = time.perf_counter()
    ecdsa_priv = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    ecdsa_pub = ecdsa_priv.get_verifying_key()
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(ecdsa_priv.to_string())
    sizes["Public Key"] = len(ecdsa_pub.to_string())

    # SPHINCS+ Key Pair Generation
    start = time.perf_counter()
    seed = os.urandom(sphincs_sha256f.crypto_sign_SEEDBYTES)
    sphincs_pub, sphincs_priv = sphincs_sha256f.generate_keypair(seed)
    timings["Key Pair Generation"] += time.perf_counter() - start
    sizes["Private Key"] += len(sphincs_priv)
    sizes["Public Key"] += len(sphincs_pub)

    # Address from ECDSA for simplicity
    start = time.perf_counter()
    address = ripemd160_sha256(ecdsa_pub.to_string()).hex()
    timings["Address Generation"] = time.perf_counter() - start

    # Transaction Setup
    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Hybrid Previous TX").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(address, 0.75)]
    timings["TX Setup"] = time.perf_counter() - start

    # Serialization
    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    # Hashing
    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    # ECDSA Signing
    start = time.perf_counter()
    ecdsa_sig = ecdsa_priv.sign(tx_hash)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(ecdsa_sig)

    # SPHINCS+ Signing
    start = time.perf_counter()
    sphincs_sig = sphincs_sha256s.sign(tx_hash, sphincs_priv)
    timings["Signing"] += time.perf_counter() - start
    sizes["Signature"] += len(sphincs_sig)

    # ECDSA Verification
    start = time.perf_counter()
    ecdsa_valid = ecdsa_pub.verify(ecdsa_sig, tx_hash)
    timings["Verification"] = time.perf_counter() - start

    # SPHINCS+ Verification
    start = time.perf_counter()
    sphincs_valid = sphincs_sha256s.verify(tx_hash, sphincs_sig, sphincs_pub)
    timings["Verification"] += time.perf_counter() - start

    return timings, sizes, ecdsa_valid and sphincs_valid


# Run all 
ecdsa_time, ecdsa_size, ecdsa_valid = run_ecdsa()
sphincs_time, sphincs_size, sphincs_valid = run_sphincs_s()
sphincs256f_time, sphincs256f_size, sphincs256f_valid = run_sphincs_sha256f()
hybrid_time, hybrid_size, hybrid_valid = run_hybrid_signature()
print(hybrid_time)
print(hybrid_size)

# Print comparisons
print_comparison_table(
    "Timing Comparison",
    (ecdsa_time, "ECDSA"),
    (sphincs_time, "SPHINCS+ SHA256s"),
    (sphincs256f_time, "SPHINCS+ SHA256f"),
    (hybrid_time, "Hybrid")
)

print_comparison_table(
    "Size Comparison",
    (ecdsa_size, "ECDSA"),
    (sphincs_size, "SPHINCS+ SHA256s"),
    (sphincs256f_size, "SPHINCS+ SHA256f"),
    (hybrid_size, "Hybrid")
)

print("\nSignature Validity")
print("------------------")
print(f"ECDSA:               {ecdsa_valid}")
print(f"SPHINCS+ SHA256s:       {sphincs_valid}")
print(f"SPHINCS+ SHA256f:    {sphincs256f_valid}")
print(f"Hybrid (Both Valid): {hybrid_valid}")
