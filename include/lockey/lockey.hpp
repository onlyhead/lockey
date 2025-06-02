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
#include <fstream>
#include <sstream>
#include <tuple>
#include <fstream>
#include <sstream>

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
    
    // IO operations for keys
    
    // Save key pair to file
    static bool saveKeyPairToFile(const crypto::KeyPair& keyPair, const std::string& filePath) {
        try {
            std::ofstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                return false;
            }
            
            // Write algorithm name
            size_t algoLength = keyPair.algorithm.length();
            file.write(reinterpret_cast<const char*>(&algoLength), sizeof(algoLength));
            file.write(keyPair.algorithm.data(), algoLength);
            
            // Write key size
            file.write(reinterpret_cast<const char*>(&keyPair.keySize), sizeof(keyPair.keySize));
            
            // Write public key
            size_t pubKeySize = keyPair.publicKey.size();
            file.write(reinterpret_cast<const char*>(&pubKeySize), sizeof(pubKeySize));
            file.write(reinterpret_cast<const char*>(keyPair.publicKey.data()), pubKeySize);
            
            // Write private key
            size_t privKeySize = keyPair.privateKey.size();
            file.write(reinterpret_cast<const char*>(&privKeySize), sizeof(privKeySize));
            file.write(reinterpret_cast<const char*>(keyPair.privateKey.data()), privKeySize);
            
            return file.good();
        } catch (const std::exception&) {
            return false;
        }
    }
    
    // Load key pair from file
    static crypto::KeyPair loadKeyPairFromFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open key file");
        }
        
        // Read algorithm name
        size_t algoLength;
        file.read(reinterpret_cast<char*>(&algoLength), sizeof(algoLength));
        std::string algorithm(algoLength, '\0');
        file.read(&algorithm[0], algoLength);
        
        // Read key size
        size_t keySize;
        file.read(reinterpret_cast<char*>(&keySize), sizeof(keySize));
        
        crypto::KeyPair keyPair(algorithm, keySize);
        
        // Read public key
        size_t pubKeySize;
        file.read(reinterpret_cast<char*>(&pubKeySize), sizeof(pubKeySize));
        keyPair.publicKey.resize(pubKeySize);
        file.read(reinterpret_cast<char*>(keyPair.publicKey.data()), pubKeySize);
        
        // Read private key
        size_t privKeySize;
        file.read(reinterpret_cast<char*>(&privKeySize), sizeof(privKeySize));
        keyPair.privateKey.resize(privKeySize);
        file.read(reinterpret_cast<char*>(keyPair.privateKey.data()), privKeySize);
        
        if (!file.good() && !file.eof()) {
            throw std::runtime_error("Error reading key file");
        }
        
        return keyPair;
    }
    
    // Save public key to file
    static bool savePublicKeyToFile(const std::vector<uint8_t>& publicKey, 
                                   const std::string& algorithm,
                                   size_t keySize,
                                   const std::string& filePath) {
        try {
            std::ofstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                return false;
            }
            
            // Write algorithm name
            size_t algoLength = algorithm.length();
            file.write(reinterpret_cast<const char*>(&algoLength), sizeof(algoLength));
            file.write(algorithm.data(), algoLength);
            
            // Write key size
            file.write(reinterpret_cast<const char*>(&keySize), sizeof(keySize));
            
            // Write public key
            size_t pubKeySize = publicKey.size();
            file.write(reinterpret_cast<const char*>(&pubKeySize), sizeof(pubKeySize));
            file.write(reinterpret_cast<const char*>(publicKey.data()), pubKeySize);
            
            return file.good();
        } catch (const std::exception&) {
            return false;
        }
    }
    
    // Overloaded version that takes a KeyPair
    static bool savePublicKeyToFile(const crypto::KeyPair& keyPair, const std::string& filePath) {
        return savePublicKeyToFile(keyPair.publicKey, keyPair.algorithm, keyPair.keySize, filePath);
    }
    
    // Load public key from file
    static std::tuple<std::vector<uint8_t>, std::string, size_t> loadPublicKeyFromFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open key file");
        }
        
        // Read algorithm name
        size_t algoLength;
        file.read(reinterpret_cast<char*>(&algoLength), sizeof(algoLength));
        std::string algorithm(algoLength, '\0');
        file.read(&algorithm[0], algoLength);
        
        // Read key size
        size_t keySize;
        file.read(reinterpret_cast<char*>(&keySize), sizeof(keySize));
        
        // Read public key
        size_t pubKeySize;
        file.read(reinterpret_cast<char*>(&pubKeySize), sizeof(pubKeySize));
        std::vector<uint8_t> publicKey(pubKeySize);
        file.read(reinterpret_cast<char*>(publicKey.data()), pubKeySize);
        
        if (!file.good() && !file.eof()) {
            throw std::runtime_error("Error reading key file");
        }
        
        return {publicKey, algorithm, keySize};
    }
    
    // Convert key to string
    static std::string keyToString(const std::vector<uint8_t>& key) {
        static crypto::CryptoManager manager;
        return manager.bytesToHex(key);
    }
    
    // Convert string to key
    static std::vector<uint8_t> stringToKey(const std::string& keyStr) {
        static crypto::CryptoManager manager;
        return manager.hexToBytes(keyStr);
    }
    
    // Convert KeyPair to string representation
    static std::string keyPairToString(const crypto::KeyPair& keyPair) {
        std::stringstream ss;
        ss << "Algorithm: " << keyPair.algorithm << "\n";
        ss << "Key Size: " << keyPair.keySize << "\n";
        ss << "Public Key: " << keyToString(keyPair.publicKey) << "\n";
        ss << "Private Key: " << keyToString(keyPair.privateKey);
        return ss.str();
    }
    
    // Parse KeyPair from string representation
    static crypto::KeyPair keyPairFromString(const std::string& str) {
        std::istringstream ss(str);
        std::string line, algorithm;
        size_t keySize = 0;
        std::vector<uint8_t> publicKey, privateKey;
        
        while (std::getline(ss, line)) {
            if (line.find("Algorithm: ") == 0) {
                algorithm = line.substr(11);
            } else if (line.find("Key Size: ") == 0) {
                keySize = std::stoul(line.substr(10));
            } else if (line.find("Public Key: ") == 0) {
                publicKey = stringToKey(line.substr(12));
            } else if (line.find("Private Key: ") == 0) {
                privateKey = stringToKey(line.substr(13));
            }
        }
        
        if (algorithm.empty() || keySize == 0 || publicKey.empty() || privateKey.empty()) {
            throw std::runtime_error("Invalid key pair string format");
        }
        
        crypto::KeyPair keyPair(algorithm, keySize);
        keyPair.publicKey = std::move(publicKey);
        keyPair.privateKey = std::move(privateKey);
        
        return keyPair;
    }
    
    // Utility functions for byte/hex conversion
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