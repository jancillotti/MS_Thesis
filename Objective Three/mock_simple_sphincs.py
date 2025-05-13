import hashlib
import os
import struct
import time
import pyspx.sha2_128s as sphincs  # SPHINCS+ variant

timings = {}
sizes = {}

# Step 1: Seed Generation
start = time.perf_counter()
seed = os.urandom(sphincs.crypto_sign_SEEDBYTES)
timings["Seed Generation"] = time.perf_counter() - start
sizes["Seed Size (bytes)"] = len(seed)

# Step 2: SPHINCS+ Key Pair Generation
start = time.perf_counter()
public_key, private_key = sphincs.generate_keypair(seed)
timings["Key Pair Generation"] = time.perf_counter() - start
sizes["Private Key Size (bytes)"] = len(private_key)
sizes["Public Key Size (bytes)"] = len(public_key)

# Step 3: Address Generation (RIPEMD160(SHA256(PK)))
def ripemd160_sha256(data):
    """Perform SHA-256 followed by RIPEMD-160 (used in Bitcoin addresses)."""
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()

start = time.perf_counter()
mock_address = ripemd160_sha256(public_key).hex()
timings["Mock Address Generation"] = time.perf_counter() - start

# Step 4: UTXO + Inputs/Outputs
start = time.perf_counter()
previous_tx_id = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
output_index = 0
tx_inputs = [(previous_tx_id, output_index)]
tx_outputs = [(mock_address, 0.5)]
timings["Mock TX + UTXO Setup"] = time.perf_counter() - start

# Step 5: Transaction Serialization
def serialize_transaction(inputs, outputs):
    """Create a Bitcoin-like transaction serialization."""
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
        satoshis = struct.pack("<Q", int(amount * 100_000_000))
        script_pubkey = b"\x76\xa9" + struct.pack("<B", 20) + bytes.fromhex(address) + b"\x88\xac"
        script_pubkey_length = struct.pack("<B", len(script_pubkey))
        tx_outputs_serialized += satoshis + script_pubkey_length + script_pubkey

    tx_locktime = struct.pack("<L", 0)
    return tx_version + tx_in_count + tx_inputs_serialized + tx_out_count + tx_outputs_serialized + tx_locktime

start = time.perf_counter()
raw_tx = serialize_transaction(tx_inputs, tx_outputs)
timings["Transaction Serialization"] = time.perf_counter() - start
sizes["Serialized Transaction Size (bytes)"] = len(raw_tx)

# Step 6: Double SHA-256 Hash
start = time.perf_counter()
tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
timings["Transaction Hashing (Double SHA-256)"] = time.perf_counter() - start

# Step 7: SPHINCS+ Signature
start = time.perf_counter()
signature = sphincs.sign(tx_hash, private_key)
timings["Signing Transaction Hash"] = time.perf_counter() - start
sizes["Signature Size (bytes)"] = len(signature)

# Step 8: SPHINCS+ Verification
start = time.perf_counter()
is_valid = sphincs.verify(tx_hash, signature, public_key)
timings["Signature Verification"] = time.perf_counter() - start

# # Output
# print("\nMock Bitcoin Transaction (SPHINCS+)")
# print("-----------------------------------")
# print("Mock Address (Recipient):", mock_address)
# print("Previous TX ID:", previous_tx_id)
# print("Serialized Transaction:", raw_tx.hex())
# print("Transaction Hash (Double SHA-256):", tx_hash.hex())
# print("Signature:", signature.hex())
print("Signature Valid:", is_valid)

# Timing chart
print("\nTiming Breakdown (in seconds)")
print("-----------------------------")
for step, duration in timings.items():
    print(f"{step:<35}: {duration:.6f}s")

# Size chart
print("\nSize Breakdown (in bytes)")
print("--------------------------")
for item, size in sizes.items():
    print(f"{item:<35}: {size} bytes")
