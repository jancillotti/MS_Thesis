#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <vector>

#include "util.h"
#include <iostream>
#include <oqs/oqs.h>
#include <chrono>
#include <vector>

static int sign_and_verify_ecdsa_falcon() {
    Botan::AutoSeeded_RNG rng;
    auto group = Botan::EC_Group::from_name("secp256k1");
    uint8_t falcon_pub[OQS_SIG_falcon_512_length_public_key];
    uint8_t falcon_priv[OQS_SIG_falcon_512_length_secret_key];
    uint8_t falcon_sig[OQS_SIG_falcon_512_length_signature];
    size_t falcon_sig_len = 0;
    OQS_STATUS rc;
    std::vector<uint8_t> message(current_message_len);
    rng.randomize(message.data(), message.size());
    // --- ECDSA Key Generation ---
    auto start  = std::chrono::high_resolution_clock::now();
    Botan::ECDSA_PrivateKey ecdsa_priv_key(rng, group);
    Botan::ECDSA_PublicKey ecdsa_pub_key = ecdsa_priv_key;

    // --- Falcon Key Generation ---

    rc = OQS_SIG_falcon_512_keypair(falcon_pub, falcon_priv);
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("Failed to generate Falcon key pair");
    }
    auto stop = std::chrono::high_resolution_clock::now();
    keygen_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());


    // --- Combine actual public keys for hybrid identity ---
    auto ecdsa_pub_bits = ecdsa_pub_key.public_key_bits();
    std::vector<uint8_t> hybrid_pubkey_bytes = ecdsa_pub_bits;
    hybrid_pubkey_bytes.insert(hybrid_pubkey_bytes.end(), falcon_pub,
                               falcon_pub + OQS_SIG_falcon_512_length_public_key);


    // --- ECDSA Signing ---
    start  = std::chrono::high_resolution_clock::now();
    Botan::PK_Signer ecdsa_signer(ecdsa_priv_key, rng, "SHA-256");
    auto sig_ecdsa = ecdsa_signer.sign_message(message, rng);

    // --- Falcon Signing ---
    if (OQS_SIG_falcon_512_sign(falcon_sig, &falcon_sig_len, message.data(), message.size(), falcon_priv) !=
        OQS_SUCCESS) {
        throw std::runtime_error("Failed to sign with Falcon");
    }
    stop = std::chrono::high_resolution_clock::now();
    sign_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());

    // --- Hybrid Verification ---
    start  = std::chrono::high_resolution_clock::now();
    Botan::PK_Verifier ecdsa_verifier(ecdsa_pub_key, "SHA-256");
    bool ecdsa_ok = ecdsa_verifier.verify_message(message, sig_ecdsa);

    bool falcon_ok = (OQS_SIG_falcon_512_verify(message.data(), message.size(),
                                                falcon_sig, falcon_sig_len, falcon_pub) == OQS_SUCCESS);
    stop = std::chrono::high_resolution_clock::now();
    verify_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    if (ecdsa_ok && falcon_ok) {
        std::cout << "Hybrid signature is valid." << std::endl;
    } else {
        std::cout << "Hybrid signature is invalid." << std::endl;
    }
    return 0;
}


int run_ecdsa_falcon_benchmark(std::ostream &out) {
    unsigned long long average_keygen, average_sign_time, average_verify_time, stddev_sign_time, stddev_verify_time,
            average_sign_cpu, average_verify_cpu;
    size_t message_sizes[] = {4, 32, 64, 128, 512, 1024, 2500, 4096};

    for (size_t msg_size: message_sizes) {
        current_message_len = msg_size;

        for (int i = 0; i < ITERATIONS; i++) {
            std::cout << "ECDSA + Falcon i=" << i << "\t";
            sign_and_verify_ecdsa_falcon();
        }
        get_average_keygen_time(average_keygen, keygen_times);
        get_average_sign_time(average_sign_time, sign_times);
        get_average_verify_time(average_verify_time, verify_times);
        get_stddev_sign(stddev_sign_time, sign_times);
        get_stddev_verify(stddev_verify_time, verify_times);
        get_average_sign_cpu_time(average_sign_cpu, sign_cpu_usgage);
        get_average_verify_cpu_time(average_verify_cpu, verify_cpu_usgage);
        out << "\n";
        out << "=== ECDSA + Falcon Results ===\n";
        out << "Message size: " << current_message_len << " bytes\n";
        record_results(average_keygen, average_sign_time, average_sign_cpu, average_verify_time,
                       average_verify_cpu, stddev_sign_time, stddev_verify_time, out);


        sign_times.clear();
        verify_times.clear();
        sign_cpu_usgage.clear();
        verify_cpu_usgage.clear();
        keygen_times.clear();

    }
    return 0;
}