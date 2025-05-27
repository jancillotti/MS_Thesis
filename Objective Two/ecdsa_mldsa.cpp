#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <vector>

#include <botan/auto_rng.h>
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>

#include <chrono>
#include <iostream>
#include <vector>

#include "util.h"

static int sign_and_verify_ecdsa_mldsa() {
    Botan::AutoSeeded_RNG rng;
    auto group = Botan::EC_Group::from_name("secp256k1");
    std::vector<uint8_t> message(current_message_len);
    rng.randomize(message.data(), message.size());
    // --- ECDSA Key Generation ---
    auto start  = std::chrono::high_resolution_clock::now();
    Botan::ECDSA_PrivateKey ecdsa_priv_key(rng, group);
    Botan::ECDSA_PublicKey ecdsa_pub_key = ecdsa_priv_key;

    // --- ML-DSA Key Generation ---

    auto priv_key = Botan::ML_DSA_PrivateKey(rng, Botan::ML_DSA_Mode(Botan::ML_DSA_Mode::ML_DSA_4x4));
    const auto pub_key = priv_key.public_key();
    auto stop = std::chrono::high_resolution_clock::now();
    keygen_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());


    // --- Combine actual public keys for hybrid identity ---
    auto ecdsa_pub_bits = ecdsa_pub_key.public_key_bits();
    auto mldsa_pub_bits = pub_key->public_key_bits();
    std::vector<uint8_t> hybrid_pubkey_bytes = ecdsa_pub_bits;
    hybrid_pubkey_bytes.insert(hybrid_pubkey_bytes.end(), mldsa_pub_bits.begin(), mldsa_pub_bits.end());

    // --- ECDSA Signing ---
    start  = std::chrono::high_resolution_clock::now();
    Botan::PK_Signer ecdsa_signer(ecdsa_priv_key, rng, "SHA-256");
    auto sig_ecdsa = ecdsa_signer.sign_message(message, rng);
    // --- ML-DSA Signing ---
    auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");
    signer.update(message.data(), message.size());
    std::vector<uint8_t> sig = signer.signature(rng);
    stop = std::chrono::high_resolution_clock::now();
    sign_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());

    // --- Hybrid Verification ---
    start  = std::chrono::high_resolution_clock::now();
    Botan::PK_Verifier ecdsa_verifier(ecdsa_pub_key, "SHA-256");
    bool ecdsa_ok = ecdsa_verifier.verify_message(message, sig_ecdsa);
    Botan::PK_Verifier mldsa_verifier(*pub_key, "");
    mldsa_verifier.update(message);
    bool mldsa_ok = mldsa_verifier.check_signature(sig);

    stop = std::chrono::high_resolution_clock::now();
    verify_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    if (ecdsa_ok && mldsa_ok) {
        std::cout << "Hybrid signature is valid." << std::endl;
    } else {
        std::cout << "Hybrid signature is invalid." << std::endl;
    }
    return 0;
}


int run_ecdsa_mldsa_benchmark(std::ostream &out) {
    unsigned long long average_keygen, average_sign_time, average_verify_time, stddev_sign_time, stddev_verify_time,
            average_sign_cpu, average_verify_cpu;
    size_t message_sizes[] = {4, 32, 64, 128, 512, 1024, 2500, 4096};

    for (size_t msg_size: message_sizes) {
        current_message_len = msg_size;

        for (int i = 0; i < ITERATIONS; i++) {
            std::cout << "ECDSA + MLDSA i=" << i << "\t";
            sign_and_verify_ecdsa_mldsa();
        }
        get_average_keygen_time(average_keygen, keygen_times);
        get_average_sign_time(average_sign_time, sign_times);
        get_average_verify_time(average_verify_time, verify_times);
        get_stddev_sign(stddev_sign_time, sign_times);
        get_stddev_verify(stddev_verify_time, verify_times);
        get_average_sign_cpu_time(average_sign_cpu, sign_cpu_usgage);
        get_average_verify_cpu_time(average_verify_cpu, verify_cpu_usgage);
        out << "\n";
        out << "=== ECDSA + MLDSA Results ===\n";
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