#pragma once
#include "interfaces.hpp"
#include "../algorithm/blake2s.hpp"

namespace lockey {
namespace crypto {

class Blake2sHasher : public Hasher {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& input) override {
        uint8_t hash[32];
        blake2s(hash, input.data(), input.size());
        return std::vector<uint8_t>(hash, hash + 32);
    }
    
    size_t getHashSize() const override {
        return 32; // BLAKE2s produces 256-bit (32-byte) hashes
    }
    
    std::string getAlgorithmName() const override {
        return "BLAKE2s";
    }
};

} // namespace crypto
} // namespace lockey
