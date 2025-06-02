#pragma once
#include "../interfaces.hpp"
#include "../../algorithm/hash/md5.hpp"

namespace lockey {
namespace crypto {

class MD5Hasher : public Hasher {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& input) override {
        uint8_t hash[16];
        md5(hash, input.data(), input.size());
        return std::vector<uint8_t>(hash, hash + 16);
    }
    
    size_t getHashSize() const override {
        return 16; // MD5 produces 128-bit (16-byte) hashes
    }
    
    std::string getAlgorithmName() const override {
        return "MD5";
    }
};

} // namespace crypto
} // namespace lockey
