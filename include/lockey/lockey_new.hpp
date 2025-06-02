#pragma once

#include "algorithm/blake2s.hpp"
#include "algorithm/cypher.hpp"
#include "algorithm/rsa_legacy.hpp"
#include "crypto/crypto_manager.hpp"
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
    
    // Legacy RSA-specific key generation for backward compatibility
    static RSAKeyPair generateRSAKeyPair(size_t keySize = 2048) {
        return RSA::generateKey(keySize);
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
    
    // Legacy functions for backward compatibility
    static std::string encrypt(const std::string& plaintext, const Cypher& e, const Cypher& n) {
        std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
        return encryptBytesLegacy(data, e, n);
    }
    
    static std::string decrypt(const std::string& ciphertext, const Cypher& d, const Cypher& n) {
        std::vector<uint8_t> decryptedBytes = decryptToBytesLegacy(ciphertext, d, n);
        return std::string(decryptedBytes.begin(), decryptedBytes.end());
    }
    
    static std::string sign(const std::string& message, const Cypher& d, const Cypher& n) {
        std::vector<uint8_t> msgBytes(message.begin(), message.end());
        Cypher signature = RSA::sign(msgBytes, d, n);
        return cypherToHex(signature);
    }
    
    static bool verify(const std::string& message, const std::string& hexSignature, const Cypher& e, const Cypher& n) {
        std::vector<uint8_t> msgBytes(message.begin(), message.end());
        Cypher signature(hexToBytes(hexSignature));
        return RSA::verify(msgBytes, signature, e, n);
    }

private:
    // Legacy helper functions
    static std::string encryptBytesLegacy(const std::vector<uint8_t>& data, const Cypher& e, const Cypher& n) {
        if (data.empty()) return "";
        
        Cypher message(data);
        
        if (message >= n) {
            throw std::runtime_error("Message too large for key size");
        }
        
        Cypher encrypted = RSA::encrypt(message, e, n);
        return cypherToHex(encrypted);
    }
    
    static std::vector<uint8_t> decryptToBytesLegacy(const std::string& hexCiphertext, const Cypher& d, const Cypher& n) {
        if (hexCiphertext.empty()) return {};
        
        Cypher encrypted(hexToBytes(hexCiphertext));
        Cypher decrypted = RSA::decrypt(encrypted, d, n);
        
        return decrypted.toBytes();
    }
    
    static std::string cypherToHex(const Cypher& num) {
        if (num.isZero()) return "0";
        
        std::string result;
        Cypher temp = num;
        Cypher sixteen(16);
        
        while (!temp.isZero()) {
            auto dm = Cypher::divMod(temp, sixteen);
            uint32_t digit = dm.second.isZero() ? 0 : dm.second.getLowLimb();
            result = "0123456789abcdef"[digit] + result;
            temp = dm.first;
        }
        
        return result;
    }
};

} // namespace lockey
