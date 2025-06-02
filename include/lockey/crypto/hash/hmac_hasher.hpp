#pragma once
#include "../interfaces.hpp"
#include "../../algorithm/hmac.hpp"
#include "../../algorithm/hash/sha256.hpp"
#include "../../algorithm/hash/sha1.hpp"
#include "../../algorithm/hash/md5.hpp"
#include "../../algorithm/blake2s.hpp"

namespace lockey {
namespace crypto {

class HMACHasher : public Hasher {
public:
    enum class Algorithm {
        SHA256,
        SHA1,
        MD5,
        BLAKE2S
    };

private:
    Algorithm algorithm_;
    std::vector<uint8_t> key_;

public:
    HMACHasher(Algorithm alg, const std::vector<uint8_t>& key) 
        : algorithm_(alg), key_(key) {}
    
    HMACHasher(Algorithm alg, const std::string& key) 
        : algorithm_(alg), key_(key.begin(), key.end()) {}

    std::vector<uint8_t> hash(const std::vector<uint8_t>& input) override {
        switch (algorithm_) {
            case Algorithm::SHA256:
                return HMAC<SHA256>::compute(key_, input, 32);
            case Algorithm::SHA1:
                return HMAC<SHA1>::compute(key_, input, 20);
            case Algorithm::MD5:
                return HMAC<MD5>::compute(key_, input, 16);
            case Algorithm::BLAKE2S:
                return HMAC<BLAKE2S>::compute(key_, input, 32);
            default:
                throw std::runtime_error("Unsupported HMAC algorithm");
        }
    }
    
    size_t getHashSize() const override {
        switch (algorithm_) {
            case Algorithm::SHA256: return 32;
            case Algorithm::SHA1: return 20;
            case Algorithm::MD5: return 16;
            case Algorithm::BLAKE2S: return 32;
            default: return 0;
        }
    }
    
    std::string getAlgorithmName() const override {
        switch (algorithm_) {
            case Algorithm::SHA256: return "HMAC-SHA256";
            case Algorithm::SHA1: return "HMAC-SHA1";
            case Algorithm::MD5: return "HMAC-MD5";
            case Algorithm::BLAKE2S: return "HMAC-BLAKE2S";
            default: return "Unknown HMAC";
        }
    }
};

} // namespace crypto
} // namespace lockey
