#include "hash_utils.h"
#include <botan/hash.h>

std::vector<uint8_t> ripemd160_sha256(const std::vector<uint8_t>& data) {
    auto sha256 = Botan::HashFunction::create("SHA-256");
    auto ripemd160 = Botan::HashFunction::create("RIPEMD-160");
    auto hash1 = sha256->process(data);
    auto hash2 = ripemd160->process(hash1);
    return std::vector<uint8_t>(hash2.begin(), hash2.end());  // FIXED
}
