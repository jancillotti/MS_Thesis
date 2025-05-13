#pragma once
#include <vector>
#include <string>
#include <utility>
#include <cstdint>

enum class Scheme { ECDSA, SPHINCSS, SPHINCSF, HYBRID, MLDSA, FALCON };

std::vector<uint8_t> serialize_transaction(const std::vector<std::pair<std::string, int>>& inputs,
                                           const std::vector<std::pair<std::string, double>>& outputs,
                                           Scheme scheme);