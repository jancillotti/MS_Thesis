#include <botan/auto_rng.h>
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>

#include <chrono>
#include <iostream>
#include <vector>

#include "util.h"

// Total time process has been actively executing on the CPU.
static long long get_cpu_time_microseconds() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    long long user_time = usage.ru_utime.tv_sec * 1'000'000 + usage.ru_utime.tv_usec;
    long long sys_time  = usage.ru_stime.tv_sec * 1'000'000 + usage.ru_stime.tv_usec;
    return user_time + sys_time;
}

static int sign_and_verify_mldsa() {
    Botan::AutoSeeded_RNG rng;

    auto start = std::chrono::high_resolution_clock::now();
    auto priv_key = Botan::ML_DSA_PrivateKey(rng, Botan::ML_DSA_Mode(Botan::ML_DSA_Mode::ML_DSA_4x4));
    const auto pub_key = priv_key.public_key();
    auto stop = std::chrono::high_resolution_clock::now();
    keygen_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());

    auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");

    Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04};

    start = std::chrono::high_resolution_clock::now();
    auto start_cpu = get_cpu_time_microseconds();

    signer.update(msg.data(), msg.size());
    std::vector<uint8_t> sig = signer.signature(rng);
    stop = std::chrono::high_resolution_clock::now();
    auto end_cpu = get_cpu_time_microseconds();


    sign_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    sign_cpu_usgage.push_back(end_cpu - start_cpu);

    // Verify
    Botan::PK_Verifier verifier(*pub_key, "");

    start = std::chrono::high_resolution_clock::now();
    start_cpu = get_cpu_time_microseconds();

    verifier.update(msg);
    std::cout << "is " << (verifier.check_signature(sig) ? "valid" : "invalid") << std::endl;

    stop = std::chrono::high_resolution_clock::now();
    end_cpu = get_cpu_time_microseconds();
    verify_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    verify_cpu_usgage.push_back(end_cpu - start_cpu);
    return 0;
}

int run_mldsa_benchmark(std::ostream& out) {
    unsigned long long average_keygen, average_sign_time, average_verify_time, stddev_sign_time, stddev_verify_time, average_sign_cpu, average_verify_cpu;
    for(int i = 0; i < ITERATIONS; i++) {
        std::cout << "ML_DSA i=" << i << "\t";
        sign_and_verify_mldsa();
    }
    get_average_keygen_time(average_keygen, keygen_times);
    get_average_sign_time(average_sign_time, sign_times);
    get_average_verify_time(average_verify_time, verify_times);
    get_stddev_sign(stddev_sign_time, sign_times);
    get_stddev_verify(stddev_verify_time, verify_times);
    get_average_sign_cpu_time(average_sign_cpu, sign_cpu_usgage);
    get_average_verify_cpu_time(average_verify_cpu, verify_cpu_usgage);
    out << "=== ML-DSA Results ===\n";
    record_results(average_keygen ,average_sign_time, average_sign_cpu, average_verify_time,
                      average_verify_cpu, stddev_sign_time, stddev_verify_time, out);

    sign_times.clear();
    verify_times.clear();
    sign_cpu_usgage.clear();
    verify_cpu_usgage.clear();

    return 0;
}