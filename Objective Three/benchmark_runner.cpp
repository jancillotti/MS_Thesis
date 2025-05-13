#include "benchmark_runner.h"
#include "transaction_serializer.h"
#include "hash_utils.h"
#include "varint.h"
#include <botan/auto_rng.h>
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/sphincsplus.h>
#include <botan/pubkey.h>
#include <botan/hash.h>
#include <chrono>
#include <vector>
#include <oqs/oqs.h>

using namespace Botan;
namespace chrono = std::chrono;

#include <botan/hash.h>

static std::vector<uint8_t> double_sha256(const std::vector<uint8_t>& input) {
    auto sha256 = Botan::HashFunction::create("SHA-256");
    auto first = sha256->process(input);
    auto second = sha256->process(first);
    return std::vector<uint8_t>(second.begin(), second.end());
}


BenchmarkResult run_ecdsa() {
    BenchmarkResult r;
    Botan::AutoSeeded_RNG rng;
    auto group = Botan::EC_Group::from_name("secp256k1");
    auto t0 = chrono::high_resolution_clock::now();
    Botan::ECDSA_PrivateKey private_key(rng, group);
    Botan::ECDSA_PublicKey public_key = private_key;
    auto t1 = chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] = chrono::duration<double, std::milli>(t1 - t0).count();
    // tbe size of the private key
    r.sizes["Private Key"] = private_key.private_key_bits().size() / 8;
    r.sizes["Public Key"] = public_key.public_key_bits().size() / 8;

    auto hash = ripemd160_sha256(public_key.public_key_bits());

    std::string txid(32, 'A');
    std::vector<std::pair<std::string, int>> inputs = {{txid, 0}};
    std::vector<std::pair<std::string, double>> outputs = {{std::string(hash.begin(), hash.end()), 0.5}};

    t0 = chrono::high_resolution_clock::now();
    auto raw_tx = serialize_transaction(inputs, outputs, Scheme::ECDSA);
    t1 = chrono::high_resolution_clock::now();
    r.timings["TX Serialization"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Transaction"] = raw_tx.size();

    auto tx_hash = double_sha256(raw_tx);

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Signer signer(private_key, rng, "EMSA1(SHA-256)");
    auto sig = signer.sign_message(tx_hash, rng);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Signing"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] = sig.size();

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Verifier verifier(private_key, "EMSA1(SHA-256)");
    r.valid = verifier.verify_message(tx_hash, sig);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Verification"] = chrono::duration<double, std::milli>(t1 - t0).count();

    return r;
}


BenchmarkResult run_mldsa() {
    BenchmarkResult r;
    Botan::AutoSeeded_RNG rng;

    auto t0 = chrono::high_resolution_clock::now();
    auto priv_key = Botan::ML_DSA_PrivateKey(rng, Botan::ML_DSA_Mode(Botan::ML_DSA_Mode::ML_DSA_4x4));
    const auto pub_key = priv_key.public_key();
    auto t1 = chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] = chrono::duration<double, std::milli>(t1 - t0).count();
    // tbe size of the private key
    r.sizes["Private Key"] = priv_key.private_key_bits().size() / 8;
    r.sizes["Public Key"] = pub_key->public_key_bits().size() / 8;

    auto hash = ripemd160_sha256(pub_key->public_key_bits());

    std::string txid(32, 'A');
    std::vector<std::pair<std::string, int>> inputs = {{txid, 0}};
    std::vector<std::pair<std::string, double>> outputs = {{std::string(hash.begin(), hash.end()), 0.5}};

    t0 = chrono::high_resolution_clock::now();
    auto raw_tx = serialize_transaction(inputs, outputs, Scheme::MLDSA);
    t1 = chrono::high_resolution_clock::now();
    r.timings["TX Serialization"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Transaction"] = raw_tx.size();

    auto tx_hash = double_sha256(raw_tx);

    t0 = chrono::high_resolution_clock::now();
    auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");
    auto sig = signer.sign_message(tx_hash, rng);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Signing"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] = sig.size();

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Verifier verifier(*pub_key, "");
    r.valid = verifier.verify_message(tx_hash, sig);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Verification"] = chrono::duration<double, std::milli>(t1 - t0).count();

    return r;
}


BenchmarkResult run_sphincs_sha2_128s() {
    BenchmarkResult r;
    AutoSeeded_RNG rng;

    auto t0 = chrono::high_resolution_clock::now();
    auto priv_key = Botan::SphincsPlus_PrivateKey(rng, Botan::Sphincs_Parameter_Set::Sphincs128Small, Botan::Sphincs_Hash_Type::Sha256);
    const auto pub_key = priv_key.public_key();
    auto t1 = chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Private Key"] = priv_key.private_key_bits().size() / 8;
    r.sizes["Public Key"] = pub_key->public_key_bits().size() / 8;

    auto hash = ripemd160_sha256(pub_key->public_key_bits());
    std::string txid(32, 'B');
    std::vector<std::pair<std::string, int>> inputs = {{txid, 0}};
    std::vector<std::pair<std::string, double>> outputs = {{std::string(hash.begin(), hash.end()), 0.5}};

    t0 = chrono::high_resolution_clock::now();
    auto raw_tx = serialize_transaction(inputs, outputs, Scheme::SPHINCSS);
    t1 = chrono::high_resolution_clock::now();
    r.timings["TX Serialization"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Transaction"] = raw_tx.size();

    auto tx_hash = double_sha256(raw_tx);

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Signer signer(priv_key, rng, "");
    auto sig = signer.sign_message(tx_hash, rng);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Signing"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] = sig.size();

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Verifier verifier(*pub_key, ""); // No padding needed
    r.valid = verifier.verify_message(tx_hash, sig);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Verification"] = chrono::duration<double, std::milli>(t1 - t0).count();

    return r;
}

BenchmarkResult run_sphincs_sha2_128f() {
    BenchmarkResult r;
    AutoSeeded_RNG rng;

    auto t0 = chrono::high_resolution_clock::now();
    auto priv_key = Botan::SphincsPlus_PrivateKey(rng, Botan::Sphincs_Parameter_Set::Sphincs128Fast,
                                                     Botan::Sphincs_Hash_Type::Sha256);
    const auto pub_key = priv_key.public_key();
    auto t1 = chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Private Key"] = priv_key.private_key_bits().size() / 8;
    r.sizes["Public Key"] = pub_key->public_key_bits().size() / 8;

    auto hash = ripemd160_sha256(pub_key->public_key_bits());
    std::string txid(32, 'C');
    std::vector<std::pair<std::string, int>> inputs = {{txid, 0}};
    std::vector<std::pair<std::string, double>> outputs = {{std::string(hash.begin(), hash.end()), 0.5}};

    t0 = chrono::high_resolution_clock::now();
    auto raw_tx = serialize_transaction(inputs, outputs, Scheme::SPHINCSF);
    t1 = chrono::high_resolution_clock::now();
    r.timings["TX Serialization"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Transaction"] = raw_tx.size();

    auto tx_hash = double_sha256(raw_tx);

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Signer signer(priv_key, rng, "");
    auto sig = signer.sign_message(tx_hash, rng);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Signing"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] = sig.size();

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Verifier verifier(*pub_key, ""); // No padding needed
    r.valid = verifier.verify_message(tx_hash, sig);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Verification"] = chrono::duration<double, std::milli>(t1 - t0).count();

    return r;
}

BenchmarkResult run_hybrid() {
    BenchmarkResult r;
    AutoSeeded_RNG rng;

    auto t0 = chrono::high_resolution_clock::now();
    auto group = Botan::EC_Group::from_name("secp256k1");
    Botan::ECDSA_PrivateKey private_key(rng, group);
    Botan::ECDSA_PublicKey public_key = private_key;
    auto t1 = chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Private Key"] = private_key.private_key_bits().size();
    r.sizes["Public Key"] = public_key.public_key_bits().size() / 8;

    t0 = chrono::high_resolution_clock::now();
    auto s_priv_key = Botan::SphincsPlus_PrivateKey(rng, Botan::Sphincs_Parameter_Set::Sphincs128Small, Botan::Sphincs_Hash_Type::Sha256);
    const auto s_pub_key = s_priv_key.public_key();
    t1 = chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] += chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Private Key"] += s_priv_key.private_key_bits().size() / 8;
    r.sizes["Public Key"] += s_pub_key->public_key_bits().size() / 8;

    auto hash = ripemd160_sha256(public_key.public_key_bits());
    std::string txid(32, 'D');
    std::vector<std::pair<std::string, int>> inputs = {{txid, 0}};
    std::vector<std::pair<std::string, double>> outputs = {{std::string(hash.begin(), hash.end()), 0.75}};

    t0 = chrono::high_resolution_clock::now();
    auto raw_tx = serialize_transaction(inputs, outputs, Scheme::HYBRID);
    t1 = chrono::high_resolution_clock::now();
    r.timings["TX Serialization"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Transaction"] = raw_tx.size();

    auto tx_hash = double_sha256(raw_tx);

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Signer signer1(private_key, rng, "EMSA1(SHA-256)");
    auto sig_ecdsa = signer1.sign_message(tx_hash, rng);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Signing"] = chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] = sig_ecdsa.size();

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Signer signer2(s_priv_key, rng, ""); // SPHINCS+ doesn't take padding options
    auto sig_sphincs = signer2.sign_message(tx_hash, rng);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Signing"] += chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] += sig_sphincs.size();

    t0 = chrono::high_resolution_clock::now();
    Botan::PK_Verifier verifier1(private_key, "EMSA1(SHA-256)");
    Botan::PK_Verifier verifier2(*s_pub_key, ""); // No padding needed
    r.valid = verifier1.verify_message(tx_hash, sig_ecdsa) && verifier2.verify_message(tx_hash, sig_sphincs);
    t1 = chrono::high_resolution_clock::now();
    r.timings["Verification"] = chrono::duration<double, std::milli>(t1 - t0).count();

    return r;
}

BenchmarkResult run_falcon() {
    BenchmarkResult r;
    Botan::AutoSeeded_RNG rng;
    uint8_t public_key[OQS_SIG_falcon_512_length_public_key];
    uint8_t secret_key[OQS_SIG_falcon_512_length_secret_key];
    uint8_t signature[OQS_SIG_falcon_512_length_signature];
    size_t signature_len = 0;
    OQS_STATUS rc;

    auto t0 = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_falcon_512_keypair(public_key, secret_key);
    auto t1 = std::chrono::high_resolution_clock::now();
    r.timings["Key Pair Generation"] = std::chrono::duration<double, std::milli>(t1 - t0).count();

    r.sizes["Private Key"] = OQS_SIG_falcon_512_length_secret_key;
    r.sizes["Public Key"] = OQS_SIG_falcon_512_length_public_key;

    auto hash = ripemd160_sha256(std::vector<uint8_t>(public_key, public_key + OQS_SIG_falcon_512_length_public_key));
    std::string txid(32, 'A');
    std::vector<std::pair<std::string, int>> inputs = {{txid, 0}};
    std::vector<std::pair<std::string, double>> outputs = {{std::string(hash.begin(), hash.end()), 0.5}};

    t0 = std::chrono::high_resolution_clock::now();
    auto raw_tx = serialize_transaction(inputs, outputs, Scheme::FALCON);
    t1 = std::chrono::high_resolution_clock::now();
    r.timings["TX Serialization"] = std::chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Transaction"] = raw_tx.size();

    auto tx_hash = double_sha256(raw_tx);

    t0 = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_falcon_512_sign(signature, &signature_len, tx_hash.data(), tx_hash.size(), secret_key);

    t1 = std::chrono::high_resolution_clock::now();
    r.timings["Signing"] = std::chrono::duration<double, std::milli>(t1 - t0).count();
    r.sizes["Signature"] = signature_len;

    t0 = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_falcon_512_verify(tx_hash.data(), tx_hash.size(), signature, signature_len, public_key);
    r.valid = (rc == OQS_SUCCESS);
    t1 = std::chrono::high_resolution_clock::now();
    r.timings["Verification"] = std::chrono::duration<double, std::milli>(t1 - t0).count();

    return r;
}