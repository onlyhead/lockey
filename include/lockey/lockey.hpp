#pragma once

#include "algorithm/blake2s.hpp"
#include "algorithm/cypher.hpp"
#include "crypto/crypto_manager.hpp"
#include "crypto/interfaces.hpp"
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <stdexcept>

namespace lockey {

// High-level universal cryptography interface
class Lockey {
public:
    // Universal key generation
    static crypto::KeyPair generateKeyPair(crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA, 
                                          size_t keySize = 2048) {
        static crypto::CryptoManager manager;
        return manager.generateKeyPair(algorithm, keySize);
    }
    
    // Universal signing
    static std::string sign(const std::string& message, 
                           const std::vector<uint8_t>& privateKey,
                           crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        auto signature = manager.sign(message, privateKey, algorithm);
        return manager.bytesToHex(signature);
    }
    
    static std::vector<uint8_t> signBytes(const std::vector<uint8_t>& message, 
                                         const std::vector<uint8_t>& privateKey,
                                         crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        return manager.sign(message, privateKey, algorithm);
    }
    
    // Universal verification
    static bool verify(const std::string& message, 
                      const std::string& hexSignature,
                      const std::vector<uint8_t>& publicKey,
                      crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        auto signature = manager.hexToBytes(hexSignature);
        return manager.verify(message, signature, publicKey, algorithm);
    }
    
    static bool verifyBytes(const std::vector<uint8_t>& message, 
                           const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& publicKey,
                           crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        return manager.verify(message, signature, publicKey, algorithm);
    }
    
    // Universal encryption
    static std::string encrypt(const std::string& plaintext, 
                              const std::vector<uint8_t>& publicKey,
                              crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        auto encrypted = manager.encrypt(plaintext, publicKey, algorithm);
        return manager.bytesToHex(encrypted);
    }
    
    static std::vector<uint8_t> encryptBytes(const std::vector<uint8_t>& plaintext, 
                                            const std::vector<uint8_t>& publicKey,
                                            crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        return manager.encrypt(plaintext, publicKey, algorithm);
    }
    
    // Universal decryption
    static std::string decrypt(const std::string& hexCiphertext, 
                              const std::vector<uint8_t>& privateKey,
                              crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        auto ciphertext = manager.hexToBytes(hexCiphertext);
        return manager.decryptToString(ciphertext, privateKey, algorithm);
    }
    
    static std::vector<uint8_t> decryptToBytes(const std::vector<uint8_t>& ciphertext, 
                                              const std::vector<uint8_t>& privateKey,
                                              crypto::CryptoManager::Algorithm algorithm = crypto::CryptoManager::Algorithm::RSA) {
        static crypto::CryptoManager manager;
        return manager.decrypt(ciphertext, privateKey, algorithm);
    }
    
    // Universal hashing
    static std::string hash(const std::string& input, 
                           crypto::CryptoManager::HashAlgorithm algorithm = crypto::CryptoManager::HashAlgorithm::BLAKE2S) {
        static crypto::CryptoManager manager;
        auto hashBytes = manager.hash(input, algorithm);
        return manager.bytesToHex(hashBytes);
    }
    
    static std::vector<uint8_t> hashBytes(const std::vector<uint8_t>& input,
                                         crypto::CryptoManager::HashAlgorithm algorithm = crypto::CryptoManager::HashAlgorithm::BLAKE2S) {
        static crypto::CryptoManager manager;
        return manager.hash(input, algorithm);
    }
    
    // Utility functions
    static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        static crypto::CryptoManager manager;
        return manager.bytesToHex(bytes);
    }
    
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        static crypto::CryptoManager manager;
        return manager.hexToBytes(hex);
    }
};

} // namespace lockey