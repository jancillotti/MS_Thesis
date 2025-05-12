#include <fstream>
#include <iostream>


// Declare the external benchmark functions
int run_mldsa_benchmark(std::ostream& out);
int run_sphincs_benchmark(std::ostream& out);
int run_sphincs_fast_benchmark(std::ostream& out);
int run_falcon_fast_benchmark(std::ostream& out);
int run_ecdsa_benchmark(std::ostream& out);


int main() {
    std::ofstream out("results.txt");
    if (!out) {
        std::cerr << "Failed to open results.txt for writing.\n";
        return 1;
    }

    run_ecdsa_benchmark(out);
    out << "\n\n";
    run_sphincs_benchmark(out);
    out << "\n\n";
    run_sphincs_fast_benchmark(out);
    out << "\n\n";
    run_falcon_fast_benchmark(out);
    out << "\n\n";
    run_mldsa_benchmark(out);
    std::cout << "Benchmarking complete. Results written to results.txt\n";
    return 0;
}
