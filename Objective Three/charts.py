import matplotlib.pyplot as plt

from sizer import df

# Signature schemes
schemes = ["ECDSA", "Falcon-512", "ML-DSA", "SPHINCS+_SHA256f", "SPHINCS+_SHA256s"]
latest = df.iloc[-1]

# Get latest values
data = []
for s in schemes:
    tx_size = latest[f"{s}_tx_size_bytes"]
    block_size = latest[f"{s}_block_size_MB"]
    max_txs = latest[f"{s}_max_txs_in_orig_block"]
    data.append([f"{tx_size:.0f}", f"{block_size:.2f}", f"{max_txs:.0f}"])

# Create table
fig, ax = plt.subplots(figsize=(10, 2))
ax.axis('off')  # no axes

# Add table
table = ax.table(
    cellText=data,
    colLabels=["Tx Size (B)", "Block Size (MB)", "Txs in 1MB"],
    rowLabels=schemes,
    cellLoc='center',
    loc='center'
)

table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 1.5)

plt.title("Signature Scheme Comparison (Latest Day)", fontsize=14)
plt.tight_layout()
plt.savefig("signature_scheme_table.png")
plt.show()


# Signature schemes
schemes = ["ECDSA", "Falcon-512", "ML-DSA", "SPHINCS+_SHA256f", "SPHINCS+_SHA256s"]

# Header
latex_table = r"""\begin{table}[htbp]
\centering
\caption{Signature Scheme Impact on Transaction Size and Block Capacity}
\begin{tabular}{|l|r|r|r|}
\hline
\textbf{Scheme} & \textbf{Tx Size (bytes)} & \textbf{Block Size (MB)} & \textbf{Txs per 1MB Block} \\
\hline
"""

# Rows
for s in schemes:
    tx_size = f"{latest[f'{s}_tx_size_bytes']:.0f}"
    block_size = f"{latest[f'{s}_block_size_MB']:.2f}"
    txs_per_mb = f"{latest[f'{s}_max_txs_in_orig_block']:.0f}"
    latex_table += f"{s.replace('_', '\\_')} & {tx_size} & {block_size} & {txs_per_mb} \\\\\n\\hline\n"

# Footer
latex_table += r"""\end{tabular}
\label{tab:signature_scheme_comparison}
\end{table}
"""

print(latex_table)
