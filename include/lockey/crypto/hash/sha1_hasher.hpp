#pragma once
#include "../interfaces.hpp"
#include "../../algorithm/hash/sha1.hpp"

namespace lockey {
namespace crypto {

class SHA1Hasher : public Hasher {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& input) override {
        uint8_t hash[20];
        sha1(hash, input.data(), input.size());
        return std::vector<uint8_t>(hash, hash + 20);
    }
    
    size_t getHashSize() const override {
        return 20; // SHA-1 produces 160-bit (20-byte) hashes
    }
    
    std::string getAlgorithmName() const override {
        return "SHA-1";
    }
};

} // namespace crypto
} // namespace lockey
