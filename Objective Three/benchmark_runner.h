#pragma once
#include <map>
#include <string>

struct BenchmarkResult {
    std::map<std::string, double> timings;
    std::map<std::string, size_t> sizes;
    bool valid;
};

BenchmarkResult run_ecdsa();
BenchmarkResult run_mldsa();
BenchmarkResult run_falcon();
BenchmarkResult run_sphincs_sha2_128s();
BenchmarkResult run_sphincs_sha2_128f();
BenchmarkResult run_hybrid();