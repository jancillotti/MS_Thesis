#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <vector>

#include "util.h"

#define ITERATIONS 1000


// Total time process has been actively executing on the CPU.
static long long get_cpu_time_microseconds() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    long long user_time = usage.ru_utime.tv_sec * 1'000'000 + usage.ru_utime.tv_usec;
    long long sys_time = usage.ru_stime.tv_sec * 1'000'000 + usage.ru_stime.tv_usec;
    return user_time + sys_time;
}


int sign_and_verify_ecdsa() {
    Botan::AutoSeeded_RNG rng;
    // Generate a new ECDSA key pair
    auto start = std::chrono::high_resolution_clock::now();

    Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group::from_name("secp256k1"));
    auto stop = std::chrono::high_resolution_clock::now();
    keygen_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());


    //Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group::from_name("secp521r1"));
    std::vector<uint8_t> message(current_message_len);
    rng.randomize(message.data(), message.size());

    Botan::PK_Signer signer(key, rng, "SHA-256");

    start = std::chrono::high_resolution_clock::now();
    auto start_cpu = get_cpu_time_microseconds();

    signer.update(message);

    std::vector<uint8_t> signature = signer.signature(rng);

    stop = std::chrono::high_resolution_clock::now();
    auto end_cpu = get_cpu_time_microseconds();

    sign_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    sign_cpu_usgage.push_back(end_cpu - start_cpu);

    Botan::PK_Verifier verifier(key, "SHA-256");

    start = std::chrono::high_resolution_clock::now();
    start_cpu = get_cpu_time_microseconds();

    verifier.update(message);
    std::cout << "is " << (verifier.check_signature(signature) ? "valid" : "invalid") << std::endl;

    stop = std::chrono::high_resolution_clock::now();
    end_cpu = get_cpu_time_microseconds();

    verify_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    verify_cpu_usgage.push_back(end_cpu - start_cpu);

    return 0;
}

int run_ecdsa_benchmark(std::ostream &out) {
    unsigned long long average_keygen, average_sign_time, average_verify_time, stddev_sign_time, stddev_verify_time,
            average_sign_cpu, average_verify_cpu;
    size_t message_sizes[] = {4, 32, 64, 128, 512, 1024, 2500, 4096};

    for (size_t msg_size: message_sizes) {
        current_message_len = msg_size;

        for (int i = 0; i < ITERATIONS; i++) {
            std::cout << "ECDSA i=" << i << "\t";
            sign_and_verify_ecdsa();
        }
        get_average_keygen_time(average_keygen, keygen_times);
        get_average_sign_time(average_sign_time, sign_times);
        get_average_verify_time(average_verify_time, verify_times);
        get_stddev_sign(stddev_sign_time, sign_times);
        get_stddev_verify(stddev_verify_time, verify_times);
        get_average_sign_cpu_time(average_sign_cpu, sign_cpu_usgage);
        get_average_verify_cpu_time(average_verify_cpu, verify_cpu_usgage);
        out << "\n";
        out << "=== ECDSA Results ===\n";
        out << "Message size: " << current_message_len << " bytes\n";
        record_results(average_keygen, average_sign_time, average_sign_cpu, average_verify_time,
                       average_verify_cpu, stddev_sign_time, stddev_verify_time, out);


        sign_times.clear();
        verify_times.clear();
        sign_cpu_usgage.clear();
        verify_cpu_usgage.clear();
    }
    return 0;
}
