#pragma once

#include "elliptic_curve.hpp"
#include <memory>

namespace lockey {
namespace ec {

class ECEngine {
public:
    virtual ~ECEngine() = default;
    virtual KeyPair generate_keypair() = 0;
    virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& hash, 
                                    const std::vector<uint8_t>& private_key) = 0;
    virtual bool verify(const std::vector<uint8_t>& hash,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key) = 0;
    virtual std::vector<uint8_t> ecdh(const std::vector<uint8_t>& private_key,
                                    const std::vector<uint8_t>& public_key) = 0;
};

class P256Engine : public ECEngine {
private:
    P256Curve curve_;
    
public:
    KeyPair generate_keypair() override {
        auto ec_keypair = curve_.generate_keypair();
        KeyPair result;
        result.private_key = ec_keypair.private_key;
        result.public_key = ec_keypair.public_key;  // Keep as Point, don't encode
        return result;
    }
    
    std::vector<uint8_t> sign(const std::vector<uint8_t>& hash, 
                            const std::vector<uint8_t>& private_key) override {
        auto signature = curve_.sign(hash, private_key);
        // Encode signature as r || s
        std::vector<uint8_t> result;
        result.insert(result.end(), signature.r.begin(), signature.r.end());
        result.insert(result.end(), signature.s.begin(), signature.s.end());
        return result;
    }
    
    bool verify(const std::vector<uint8_t>& hash,
               const std::vector<uint8_t>& signature,
               const std::vector<uint8_t>& public_key) override {
        if (signature.size() != 64) return false; // r + s = 32 + 32 bytes
        
        Signature sig;
        sig.r.assign(signature.begin(), signature.begin() + 32);
        sig.s.assign(signature.begin() + 32, signature.end());
        
        auto public_point = curve_.decode_point(public_key);
        return curve_.verify(hash, sig, public_point);
    }
    
    std::vector<uint8_t> ecdh(const std::vector<uint8_t>& private_key,
                            const std::vector<uint8_t>& public_key) override {
        auto public_point = curve_.decode_point(public_key);
        auto shared_point = curve_.point_multiply(public_point, private_key);
        return curve_.encode_point(shared_point);
    }
};

} // namespace ec
} // namespace lockey
