#include "varint.h"

std::vector<uint8_t> encode_varint(uint64_t i) {
    std::vector<uint8_t> out;
    if (i < 0xfd) {
        out.push_back(static_cast<uint8_t>(i));
    } else if (i <= 0xffff) {
        out = {0xfd, static_cast<uint8_t>(i & 0xff), static_cast<uint8_t>((i >> 8) & 0xff)};
    } else if (i <= 0xffffffff) {
        out.push_back(0xfe);
        for (int j = 0; j < 4; ++j)
            out.push_back((i >> (8 * j)) & 0xff);
    } else {
        out.push_back(0xff);
        for (int j = 0; j < 8; ++j)
            out.push_back((i >> (8 * j)) & 0xff);
    }
    return out;
}
