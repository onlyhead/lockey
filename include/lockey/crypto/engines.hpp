#pragma once

#include "algorithms.hpp"
#include <memory>

namespace lockey {
namespace crypto {

class CryptoEngine {
public:
    virtual ~CryptoEngine() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key, 
                                       const std::vector<uint8_t>& plaintext,
                                       const std::vector<uint8_t>& nonce = {}) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& nonce = {}) = 0;
    virtual size_t key_size() const = 0;
    virtual size_t nonce_size() const = 0;
};

class AESGCMEngine : public CryptoEngine {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key, 
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& nonce = {}) override {
        AES_GCM aes_gcm(key);
        return aes_gcm.encrypt(plaintext, nonce);
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& ciphertext,
                               const std::vector<uint8_t>& nonce = {}) override {
        AES_GCM aes_gcm(key);
        return aes_gcm.decrypt(ciphertext, nonce);
    }
    
    size_t key_size() const override { return 32; } // AES-256
    size_t nonce_size() const override { return 12; } // GCM standard
};

class ChaCha20Engine : public CryptoEngine {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key, 
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& nonce = {}) override {
        ChaCha20 chacha(key, nonce);
        return chacha.encrypt(plaintext);
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& ciphertext,
                               const std::vector<uint8_t>& nonce = {}) override {
        ChaCha20 chacha(key, nonce);
        return chacha.decrypt(ciphertext);
    }
    
    size_t key_size() const override { return 32; } // ChaCha20
    size_t nonce_size() const override { return 12; } // ChaCha20
};

} // namespace crypto
} // namespace lockey
