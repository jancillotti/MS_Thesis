#include "transaction_serializer.h"
#include "varint.h"

std::vector<uint8_t> serialize_transaction(
    const std::vector<std::pair<std::string, int>>& inputs,
    const std::vector<std::pair<std::string, double>>& outputs,
    Scheme scheme) {

    std::vector<uint8_t> tx;

    // Version
    tx.insert(tx.end(), {0x01, 0x00, 0x00, 0x00});

    // Input count
    tx.push_back(static_cast<uint8_t>(inputs.size()));

    for (const auto& [txid_hex, index] : inputs) {
        std::vector<uint8_t> txid(txid_hex.rbegin(), txid_hex.rend());
        tx.insert(tx.end(), txid.begin(), txid.end());

        for (int i = 0; i < 4; ++i)
            tx.push_back((index >> (8 * i)) & 0xff);

        std::vector<uint8_t> dummy_sig, dummy_pub;

        switch (scheme) {
            case Scheme::ECDSA:
                dummy_sig = std::vector<uint8_t>(64, 0);
                dummy_sig[0] = 0x30;
                dummy_sig[1] = 64;
                dummy_pub = {0x02};
                dummy_pub.insert(dummy_pub.end(), 64, 0x00);
                break;
            case Scheme::SPHINCSF:
                dummy_sig = std::vector<uint8_t>(17088, 0);
                dummy_pub = std::vector<uint8_t>(32, 0);
                break;
            case Scheme::SPHINCSS:
                dummy_sig = std::vector<uint8_t>(7856, 0);
                dummy_pub = std::vector<uint8_t>(32, 0);
                break;
            case Scheme::HYBRID:
                dummy_sig = {0x30, 64};
                dummy_sig.insert(dummy_sig.end(), 64, 0x00);
                dummy_sig.insert(dummy_sig.end(), 7856, 0x00);
                dummy_pub = {0x02};
                dummy_pub.insert(dummy_pub.end(), 64, 0x00);
                dummy_pub.insert(dummy_pub.end(), 32, 0x00);
                break;
            case Scheme::MLDSA:
                dummy_sig = std::vector<uint8_t>(2420, 0);
                dummy_pub = std::vector<uint8_t>(1312, 0);
            case Scheme::FALCON:
                dummy_sig = std::vector<uint8_t>(690, 0);
                dummy_pub = std::vector<uint8_t>(890, 0);
            break;
        }

        auto sig_len = encode_varint(dummy_sig.size());
        auto pub_len = encode_varint(dummy_pub.size());

        std::vector<uint8_t> script_sig = sig_len;
        script_sig.insert(script_sig.end(), dummy_sig.begin(), dummy_sig.end());
        script_sig.insert(script_sig.end(), pub_len.begin(), pub_len.end());
        script_sig.insert(script_sig.end(), dummy_pub.begin(), dummy_pub.end());

        auto script_len = encode_varint(script_sig.size());
        tx.insert(tx.end(), script_len.begin(), script_len.end());
        tx.insert(tx.end(), script_sig.begin(), script_sig.end());

        tx.insert(tx.end(), {0xff, 0xff, 0xff, 0xff});  // sequence
    }

    tx.push_back(static_cast<uint8_t>(outputs.size()));
    for (const auto& [addr, amount] : outputs) {
        uint64_t sats = static_cast<uint64_t>(amount * 100000000);
        for (int i = 0; i < 8; ++i)
            tx.push_back((sats >> (8 * i)) & 0xff);

        std::vector<uint8_t> addr_bytes(addr.begin(), addr.end());
        std::vector<uint8_t> script = {0x76, 0xa9, 0x14};  // OP_DUP OP_HASH160 PUSH_20
        script.insert(script.end(), addr_bytes.begin(), addr_bytes.end());
        script.push_back(0x88);  // OP_EQUALVERIFY
        script.push_back(0xac);  // OP_CHECKSIG

        tx.push_back(static_cast<uint8_t>(script.size()));
        tx.insert(tx.end(), script.begin(), script.end());
    }

    tx.insert(tx.end(), {0x00, 0x00, 0x00, 0x00});  // locktime
    return tx;
}
