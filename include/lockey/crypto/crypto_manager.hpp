#pragma once
#include "interfaces.hpp"
#include "asymmetric/rsa_crypto.hpp"
#include "hash/blake2s_hasher.hpp"
#include "hash/sha256_hasher.hpp"
#include "hash/sha1_hasher.hpp"
#include "hash/md5_hasher.hpp"
#include <unordered_map>
#include <memory>
#include <stdexcept>

namespace lockey {
namespace crypto {

class CryptoManager {
public:
    enum class Algorithm {
        RSA,
        // Future algorithms can be added here
        // ECDSA,
        // ED25519,
        // AES,
        // etc.
    };
    
    enum class HashAlgorithm {
        BLAKE2S,
        SHA256,
        SHA1,
        MD5,
        // Future hash algorithms can be added here
        // SHA384,
        // SHA512,
        // SHA3,
        // etc.
    };

    CryptoManager() {
        // Register available algorithms
        registerAlgorithms();
    }

    // Universal key generation
    KeyPair generateKeyPair(Algorithm algorithm, size_t keySize = 2048) {
        auto it = keyGenerators.find(algorithm);
        if (it == keyGenerators.end()) {
            throw std::runtime_error("Unsupported key generation algorithm");
        }
        return it->second->generateKeyPair(keySize);
    }

    // Universal signing
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message, 
                             const std::vector<uint8_t>& privateKey,
                             Algorithm algorithm) {
        auto it = signers.find(algorithm);
        if (it == signers.end()) {
            throw std::runtime_error("Unsupported signing algorithm");
        }
        return it->second->sign(message, privateKey);
    }
    
    std::vector<uint8_t> sign(const std::string& message, 
                             const std::vector<uint8_t>& privateKey,
                             Algorithm algorithm) {
        std::vector<uint8_t> msgBytes(message.begin(), message.end());
        return sign(msgBytes, privateKey, algorithm);
    }

    // Universal verification
    bool verify(const std::vector<uint8_t>& message, 
               const std::vector<uint8_t>& signature,
               const std::vector<uint8_t>& publicKey,
               Algorithm algorithm) {
        auto it = signers.find(algorithm);
        if (it == signers.end()) {
            throw std::runtime_error("Unsupported verification algorithm");
        }
        return it->second->verify(message, signature, publicKey);
    }
    
    bool verify(const std::string& message, 
               const std::vector<uint8_t>& signature,
               const std::vector<uint8_t>& publicKey,
               Algorithm algorithm) {
        std::vector<uint8_t> msgBytes(message.begin(), message.end());
        return verify(msgBytes, signature, publicKey, algorithm);
    }

    // Universal encryption
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& publicKey,
                                Algorithm algorithm) {
        auto it = encryptors.find(algorithm);
        if (it == encryptors.end()) {
            throw std::runtime_error("Unsupported encryption algorithm");
        }
        return it->second->encrypt(plaintext, publicKey);
    }
    
    std::vector<uint8_t> encrypt(const std::string& plaintext,
                                const std::vector<uint8_t>& publicKey,
                                Algorithm algorithm) {
        std::vector<uint8_t> ptBytes(plaintext.begin(), plaintext.end());
        return encrypt(ptBytes, publicKey, algorithm);
    }

    // Universal decryption
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const std::vector<uint8_t>& privateKey,
                                Algorithm algorithm) {
        auto it = encryptors.find(algorithm);
        if (it == encryptors.end()) {
            throw std::runtime_error("Unsupported decryption algorithm");
        }
        return it->second->decrypt(ciphertext, privateKey);
    }
    
    std::string decryptToString(const std::vector<uint8_t>& ciphertext,
                               const std::vector<uint8_t>& privateKey,
                               Algorithm algorithm) {
        auto decrypted = decrypt(ciphertext, privateKey, algorithm);
        return std::string(decrypted.begin(), decrypted.end());
    }

    // Universal hashing
    std::vector<uint8_t> hash(const std::vector<uint8_t>& input, 
                             HashAlgorithm algorithm = HashAlgorithm::BLAKE2S) {
        auto it = hashers.find(algorithm);
        if (it == hashers.end()) {
            throw std::runtime_error("Unsupported hash algorithm");
        }
        return it->second->hash(input);
    }
    
    std::vector<uint8_t> hash(const std::string& input, 
                             HashAlgorithm algorithm = HashAlgorithm::BLAKE2S) {
        std::vector<uint8_t> inputBytes(input.begin(), input.end());
        return hash(inputBytes, algorithm);
    }

    // Utility functions
    std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        std::string result;
        for (uint8_t byte : bytes) {
            result += "0123456789abcdef"[byte >> 4];
            result += "0123456789abcdef"[byte & 0x0F];
        }
        return result;
    }
    
    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> result;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtoul(byteStr.c_str(), nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }

    // Get available algorithms
    std::vector<Algorithm> getAvailableKeyGenAlgorithms() const {
        std::vector<Algorithm> algorithms;
        for (const auto& pair : keyGenerators) {
            algorithms.push_back(pair.first);
        }
        return algorithms;
    }
    
    std::vector<HashAlgorithm> getAvailableHashAlgorithms() const {
        std::vector<HashAlgorithm> algorithms;
        for (const auto& pair : hashers) {
            algorithms.push_back(pair.first);
        }
        return algorithms;
    }

private:
    std::unordered_map<Algorithm, std::unique_ptr<KeyGenerator>> keyGenerators;
    std::unordered_map<Algorithm, std::unique_ptr<DigitalSigner>> signers;
    std::unordered_map<Algorithm, std::unique_ptr<Encryptor>> encryptors;
    std::unordered_map<HashAlgorithm, std::unique_ptr<Hasher>> hashers;

    void registerAlgorithms() {
        // Register RSA
        keyGenerators[Algorithm::RSA] = std::make_unique<RSAKeyGenerator>();
        signers[Algorithm::RSA] = std::make_unique<RSADigitalSigner>();
        encryptors[Algorithm::RSA] = std::make_unique<RSAEncryptor>();
        
        // Register hash algorithms
        hashers[HashAlgorithm::BLAKE2S] = std::make_unique<Blake2sHasher>();
        hashers[HashAlgorithm::SHA256] = std::make_unique<SHA256Hasher>();
        hashers[HashAlgorithm::SHA1] = std::make_unique<SHA1Hasher>();
        hashers[HashAlgorithm::MD5] = std::make_unique<MD5Hasher>();
        
        // Future algorithms can be registered here
    }
};

} // namespace crypto
} // namespace lockey
