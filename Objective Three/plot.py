import matplotlib.pyplot as plt

from sizer import df

# Signature schemes to compare
schemes = ["ECDSA", "Falcon-512", "ML-DSA", "SPHINCS+_SHA256f", "SPHINCS+_SHA256s"]

# Get most recent row
latest = df.iloc[-1]

# Plot setup
fig, axs = plt.subplots(3, 1, figsize=(10, 15))
fig.suptitle("Signature Scheme Impact on Bitcoin Transactions", fontsize=16)

# --- 1. Avg Transaction Size ---
tx_sizes = [latest[f"{s}_tx_size_bytes"] for s in schemes]
bars = axs[0].bar(schemes, tx_sizes)
axs[0].set_title("Average Transaction Size (bytes)")
axs[0].set_ylabel("Bytes")
axs[0].tick_params(axis='x', rotation=15)
for bar in bars:
    height = bar.get_height()
    axs[0].text(bar.get_x() + bar.get_width()/2, height, f"{height:.0f}", ha='center', va='bottom', fontsize=9)

# --- 2. Projected Block Size ---
block_sizes = [latest[f"{s}_block_size_MB"] for s in schemes]
bars = axs[1].bar(schemes, block_sizes, color='skyblue')
axs[1].set_title("Projected Block Size (MB)")
axs[1].set_ylabel("MB")
axs[1].axhline(y=4.0, color='red', linestyle='--', label="4 MB Limit")
axs[1].legend()
axs[1].tick_params(axis='x', rotation=15)
for bar in bars:
    height = bar.get_height()
    axs[1].text(bar.get_x() + bar.get_width()/2, height, f"{height:.2f}", ha='center', va='bottom', fontsize=9)

# --- 3. Transactions per 1MB Block ---
max_txs = [latest[f"{s}_max_txs_in_orig_block"] for s in schemes]
bars = axs[2].bar(schemes, max_txs)
axs[2].set_title("Max Transactions in a Block")
axs[2].set_ylabel("Transactions")
axs[2].tick_params(axis='x', rotation=15)
for bar in bars:
    height = bar.get_height()
    axs[2].text(bar.get_x() + bar.get_width()/2, height, f"{height:.0f}", ha='center', va='bottom', fontsize=9)

# Final layout
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig("signature_scheme_comparison.png")
plt.show()
