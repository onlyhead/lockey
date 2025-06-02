#pragma once
#include "../interfaces.hpp"
#include "../../algorithm/hash/sha256.hpp"

namespace lockey {
namespace crypto {

class SHA256Hasher : public Hasher {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& input) override {
        uint8_t hash[32];
        sha256(hash, input.data(), input.size());
        return std::vector<uint8_t>(hash, hash + 32);
    }
    
    size_t getHashSize() const override {
        return 32; // SHA-256 produces 256-bit (32-byte) hashes
    }
    
    std::string getAlgorithmName() const override {
        return "SHA-256";
    }
};

} // namespace crypto
} // namespace lockey
