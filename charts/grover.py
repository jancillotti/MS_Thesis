import matplotlib.pyplot as plt
import numpy as np

# Create a logarithmic scale
N = np.logspace(0, 12, base=2, num=50)  # N from 1 to 4096 in log base 2 steps

# Define "Steps" for Linear and Quadratic
linear_steps = N
quadratic_steps = np.sqrt(N)  # Equivalent to speedup from N -> sqrt(N)

# Plotting
plt.figure(figsize=(8, 6))
plt.plot(N, linear_steps, label='Linear Speed Up', color='blue')
plt.plot(N, quadratic_steps, label='Quadratic Speed Up', color='red')

plt.xscale('log', base=2)
plt.yscale('log', base=2)

plt.xlabel('N')
plt.ylabel('Steps')
plt.title('Speed Up Comparison')
plt.grid(True, which="both", ls="--", linewidth=0.5)
plt.legend()

plt.tight_layout()
plt.show()
