//
// Created by Jessica Miller on 3/23/25.
//


#include <iostream>
#include <oqs/oqs.h>
#include <chrono>
#include <vector>

#include "util.h"

#define MESSAGE_LEN 2500
#define ITERATIONS 1000


static long long get_cpu_time_microseconds() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    long long user_time = usage.ru_utime.tv_sec * 1'000'000 + usage.ru_utime.tv_usec;
    long long sys_time  = usage.ru_stime.tv_sec * 1'000'000 + usage.ru_stime.tv_usec;
    return user_time + sys_time;
}

int sign_and_verify_falcon() {

    OQS_STATUS rc;

    uint8_t public_key[OQS_SIG_falcon_512_length_public_key];
    uint8_t secret_key[OQS_SIG_falcon_512_length_secret_key];
    uint8_t message[current_message_len];
    uint8_t signature[OQS_SIG_falcon_512_length_signature];
    size_t message_len = current_message_len;
    size_t signature_len;

    OQS_randombytes(message, message_len);

    auto start = std::chrono::high_resolution_clock::now();

    rc = OQS_SIG_falcon_512_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        exit(EXIT_FAILURE);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    keygen_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());

    // Sign
    start = std::chrono::high_resolution_clock::now();
    auto start_cpu = get_cpu_time_microseconds();

    rc = OQS_SIG_falcon_512_sign(signature, &signature_len, message, message_len, secret_key);
    stop = std::chrono::high_resolution_clock::now();
    auto end_cpu = get_cpu_time_microseconds();

    // Record sign time and CPU usage
    sign_cpu_usgage.push_back(end_cpu - start_cpu);
    sign_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());

    start = std::chrono::high_resolution_clock::now();
    start_cpu = get_cpu_time_microseconds();
    if (rc != OQS_SUCCESS) {
        std::cerr << "Signing failed.\n";
        return 1;
    }
    // Verify
    rc = OQS_SIG_falcon_512_verify(message, message_len, signature, signature_len, public_key);

    if (rc == OQS_SUCCESS) {
        std::cout << "is valid." << std::endl;
        stop = std::chrono::high_resolution_clock::now();
        end_cpu = get_cpu_time_microseconds();

        // Record verify time and CPU usage
        verify_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
        verify_cpu_usgage.push_back(end_cpu - start_cpu);

        return 0;
    }
    else {
        std::cout << "Error." << std::endl;
        return 1;
    }

}

int run_falcon_fast_benchmark(std::ostream& out) {
    unsigned long long average_keygen, average_sign_time, average_verify_time, stddev_sign_time, stddev_verify_time, average_sign_cpu, average_verify_cpu;
    size_t message_sizes[] = {4, 32, 64, 128, 512, 1024, 2500, 4096};

    for (size_t msg_size: message_sizes) {
        current_message_len = msg_size;
        for (int i = 0; i < ITERATIONS; i++) {
            std::cout << "Falcon i=" << i << "\t";
            sign_and_verify_falcon();
        }
        get_average_keygen_time(average_keygen, keygen_times);
        get_average_sign_time(average_sign_time, sign_times);
        get_average_verify_time(average_verify_time, verify_times);
        get_stddev_sign(stddev_sign_time, sign_times);
        get_stddev_verify(stddev_verify_time, verify_times);
        get_average_sign_cpu_time(average_sign_cpu, sign_cpu_usgage);
        get_average_verify_cpu_time(average_verify_cpu, verify_cpu_usgage);
        out << "\n";

        out << "=== Falcon Results ===\n";
        out << "Message size: " << current_message_len << " bytes\n";
        record_results(average_keygen ,average_sign_time, average_sign_cpu, average_verify_time,
                          average_verify_cpu, stddev_sign_time, stddev_verify_time, out);


        sign_times.clear();
        verify_times.clear();
        sign_cpu_usgage.clear();
        verify_cpu_usgage.clear();
        keygen_times.clear();

    }
    return 0;
}