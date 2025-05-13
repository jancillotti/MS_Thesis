from generate_certs import generate_certs
from tsl_test import run_test
import statistics

ITERATIONS = 100

def main():
    certs = generate_certs()

    results = [("Algorithm", "Avg Handshake Time (s)", "Certificate Size")]
    port = 4437

    for name, (crt, key) in certs.items():
        times = []

        for _ in range(ITERATIONS):
            result = run_test(name, crt, key, port)
            if isinstance(result, tuple) and len(result) == 3:
                _, handshake_time, cert_size = result
                try:
                    times.append(float(handshake_time))
                except ValueError:
                    print(f"[!] Invalid time format for {name}: {handshake_time}")
                    continue

        if times:
            avg_time = statistics.mean(times)
            results.append((name, f"{avg_time:.6f}", cert_size))
        else:
            results.append((name, "N/A", cert_size))

        port += 1

    print("\n### TLS Handshake Results ###")
    for row in results:
        print(" | ".join(row))

    with open("results.md", "w") as f:
        f.write("### TLS Handshake Results\n\n")
        f.write("Algorithm | Avg Handshake Time (s) | Certificate Size\n")
        f.write("--------- | ----------------------- | ----------------\n")
        for row in results:
            f.write(" | ".join(row) + "\n")

if __name__ == "__main__":
    main()
