#include "benchmark_runner.h"
#include <iostream>
#include <iomanip>
#include <set>

void print_table(const std::string& title,
                 const std::vector<std::pair<std::map<std::string, double>, std::string>>& data);

BenchmarkResult average_results(std::function<BenchmarkResult()> fn, int iterations) {
    BenchmarkResult total;
    for (int i = 0; i < iterations; ++i) {
        BenchmarkResult r = fn();

        for (const auto& [k, v] : r.timings) total.timings[k] += v;
        for (const auto& [k, v] : r.sizes)   total.sizes[k]   += v;

        // if r.valid is false print out the error
        if (!r.valid) {
            std::cout << "Error: Signature verification failed.\n";
        }
        // else save  valid check as true
        else {
            total.valid = r.valid;  // All must be valid for final result to be valid
            }
    }

    for (auto& [k, v] : total.timings) v /= iterations;
    for (auto& [k, v] : total.sizes)   v /= iterations;

    return total;
}

int main() {
    const int ITERATIONS = 100;

    auto ecdsa   = average_results(run_ecdsa, ITERATIONS);
    auto mldsa   = average_results(run_mldsa, ITERATIONS);
    auto falcon  = average_results(run_falcon, ITERATIONS);
    auto s_s     = average_results(run_sphincs_sha2_128s, ITERATIONS);
    auto s_f     = average_results(run_sphincs_sha2_128f, ITERATIONS);
    auto hybrid  = average_results(run_hybrid, ITERATIONS);

    print_table("Timing (ms)", {
        {ecdsa.timings, "ECDSA"},
        {mldsa.timings, "ML-DSA"},
        {falcon.timings, "FALCON"},
        {s_s.timings, "SPHINCS+ s"},
        {s_f.timings, "SPHINCS+ f"},
        {hybrid.timings, "Hybrid"}
    });

    print_table("Size (bytes)", {
        {std::map<std::string, double>(ecdsa.sizes.begin(), ecdsa.sizes.end()), "ECDSA"},
        {std::map<std::string, double>(mldsa.sizes.begin(), mldsa.sizes.end()), "ML-DSA"},
        {std::map<std::string, double>(falcon.sizes.begin(), falcon.sizes.end()), "FALCON"},
        {std::map<std::string, double>(s_s.sizes.begin(), s_s.sizes.end()), "SPHINCS+ s"},
        {std::map<std::string, double>(s_f.sizes.begin(), s_f.sizes.end()), "SPHINCS+ f"},
        {std::map<std::string, double>(hybrid.sizes.begin(), hybrid.sizes.end()), "Hybrid"}
    });

    std::cout << "\nSignature Validity:\n";
    std::cout << "ECDSA: " << ecdsa.valid << "\n";
    std::cout << "ML-DSA: " << mldsa.valid << "\n";
    std::cout << "FALCON: " << falcon.valid << "\n";
    std::cout << "SPHINCS+ s: " << s_s.valid << "\n";
    std::cout << "SPHINCS+ f: " << s_f.valid << "\n";
    std::cout << "Hybrid: " << hybrid.valid << "\n";
}

void print_table(const std::string& title,
                 const std::vector<std::pair<std::map<std::string, double>, std::string>>& data) {
    std::cout << "\n" << title << "\n";
    std::cout << std::string(title.size(), '-') << "\n";
    std::cout << std::left << std::setw(25) << "Step";
    for (const auto& [_, label] : data)
        std::cout << std::setw(18) << label;
    std::cout << "\n";

    std::set<std::string> keys;
    for (const auto& [map, _] : data)
        for (const auto& [key, _] : map)
            keys.insert(key);

    for (const auto& key : keys) {
        std::cout << std::left << std::setw(25) << key;
        for (const auto& [map, _] : data) {
            auto it = map.find(key);
            if (it != map.end())
                std::cout << std::setw(18) << std::fixed << std::setprecision(3) << it->second;
            else
                std::cout << std::setw(18) << "-";
        }
        std::cout << "\n";
    }
}
