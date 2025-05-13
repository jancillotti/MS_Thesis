import json
import pandas as pd

# Load data
with open("avg-block-size-2.json") as f:
    avg_block_size_data = json.load(f)["avg-block-size"]

with open("n-transactions-per-block.json") as f:
    txs_per_block_data = json.load(f)["n-transactions-per-block"]

# Convert to DataFrames
df_block = pd.DataFrame([(e["x"], e["y"]) for e in avg_block_size_data], columns=["timestamp", "avg_block_MB"])
df_txs = pd.DataFrame([(e["x"], e["y"]) for e in txs_per_block_data], columns=["timestamp", "txs_per_block"])

# Merge and convert timestamp
df = pd.merge(df_block, df_txs, on="timestamp")
df["date"] = pd.to_datetime(df["timestamp"], unit="ms")

# Constants
BLOCK_HEADER_SIZE = 80  # bytes
MB_TO_BYTES = 1_000_000

# Signature + public key sizes in bytes
signature_schemes = {
    "ECDSA": 33 + 71,
    "Falcon-512": 897 + 1330,
    "ML-DSA": 128 + 2700,
    "SPHINCS+_SHA256f": 32 + 17088,
    "SPHINCS+_SHA256s": 32 + 7856
}

# Compute original average tx size
df["avg_tx_size_bytes"] = ((df["avg_block_MB"] * MB_TO_BYTES) - BLOCK_HEADER_SIZE) / df["txs_per_block"]

# For each scheme, calculate new tx size, block size, and max txs per original block
for name, sig_size in signature_schemes.items():
    df[f"{name}_tx_size_bytes"] = df["avg_tx_size_bytes"] - signature_schemes["ECDSA"] + sig_size
    df[f"{name}_block_size_MB"] = (df[f"{name}_tx_size_bytes"] * df["txs_per_block"] + BLOCK_HEADER_SIZE) / MB_TO_BYTES
    df[f"{name}_max_txs_in_orig_block"] = ((df["avg_block_MB"] * MB_TO_BYTES) - BLOCK_HEADER_SIZE) / df[f"{name}_tx_size_bytes"]

# Select and export
columns = ["date", "avg_tx_size_bytes"] + \
          [f"{name}_tx_size_bytes" for name in signature_schemes] + \
          [f"{name}_block_size_MB" for name in signature_schemes] + \
          [f"{name}_max_txs_in_orig_block" for name in signature_schemes]

df[columns].to_csv("signature_scheme_block_comparison.csv", index=False)
print(df[columns].head())
