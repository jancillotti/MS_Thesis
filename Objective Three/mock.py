import hashlib
import ecdsa
import struct
import time

timings = {}
sizes = {}

# Step 1: Key Generation
curve = ecdsa.SECP256k1
start = time.perf_counter()
# split the curve genration
private_key = ecdsa.SigningKey.generate(curve)
public_key = private_key.get_verifying_key()
timings["Key Pair Generation"] = time.perf_counter() - start

# Size tracking for keys
sizes["Private Key Size (bytes)"] = len(private_key.to_string())
sizes["Public Key Size (bytes)"] = len(public_key.to_string())

# Step 2: Address Generation
def ripemd160_sha256(data):
    """Perform SHA-256 followed by RIPEMD-160 (used in Bitcoin addresses)."""
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()

start = time.perf_counter()
mock_address = ripemd160_sha256(public_key.to_string()).hex()
timings["Mock Address Generation"] = time.perf_counter() - start

# Step 3: UTXO + Inputs/Outputs
start = time.perf_counter()
previous_tx_id = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
output_index = 0
tx_inputs = [(previous_tx_id, output_index)]
tx_outputs = [(mock_address, 0.5)]
timings["Mock TX + UTXO Setup"] = time.perf_counter() - start

# Step 4: Transaction Serialization
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

# Step 5: Double SHA-256 Hash
start = time.perf_counter()
tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
timings["Transaction Hashing (Double SHA-256)"] = time.perf_counter() - start

# Step 6: ECDSA Sign
start = time.perf_counter()
signature = private_key.sign(tx_hash)
timings["Signing Transaction Hash"] = time.perf_counter() - start
sizes["Signature Size (bytes)"] = len(signature)

# Step 7: Verify Signature
start = time.perf_counter()
is_valid = public_key.verify(signature, tx_hash)
timings["Signature Verification"] = time.perf_counter() - start

# # Output
# print("\nMock Bitcoin Transaction")
# print("-------------------------")
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
    print(f"{step:<40}: {duration * 1000:.3f} ms")

# Size chart
print("\nSize Breakdown (in bytes)")
print("--------------------------")
for item, size in sizes.items():
    print(f"{item:<35}: {size} bytes")
