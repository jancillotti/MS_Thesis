import matplotlib.pyplot as plt
import numpy as np

# Labels and data
schemes = ["ECDSA", "Dilithium", "Falcon", "SPHINCS+ Robust", "SPHINCS+ Simple"]
public_keys = np.array([64, 1312, 897, 32, 32])
signatures = np.array([64, 2420, 690, 7856, 17088])
bsm_overhead = np.array([162, 2580, 872, 7956, 17256])  # Total overhead (includes signed BSM, etc.)

bar_width = 0.5
index = np.arange(len(schemes))

# Plot
fig, ax = plt.subplots(figsize=(10, 6))
ax.bar(index, public_keys, bar_width, label='Public Key')
ax.bar(index, signatures, bar_width, bottom=public_keys, label='Signature')
ax.bar(index, bsm_overhead, bar_width, bottom=public_keys + signatures, label='Signed BSM + Overhead')

# Labels and formatting
ax.set_xlabel('Signature Scheme')
ax.set_ylabel('Bytes')
ax.set_title('Stacked Frame Size (ECDSA and PQC) vs. DSRC Payload Constraint')
ax.set_xticks(index)
ax.set_xticklabels(schemes)
ax.axhline(y=2304, color='red', linestyle='--', label='DSRC Frame Limit')
ax.legend()

plt.tight_layout()
plt.show()
