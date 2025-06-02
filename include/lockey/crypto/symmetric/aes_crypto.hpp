#pragma once
#include "../interfaces.hpp"
#include "../../algorithm/aes.hpp"
#include <memory>

namespace lockey {
namespace crypto {

/**
 * @brief AES Key Pair (symmetric key)
 */
struct AESKeyPair : public KeyPair {
    std::vector<uint8_t> symmetric_key;
    AES::KeySize key_size;
    
    AESKeyPair(size_t keyBits) : KeyPair("AES", keyBits) {
        switch (keyBits) {
            case 128: key_size = AES::KeySize::AES_128; break;
            case 192: key_size = AES::KeySize::AES_192; break;
            case 256: key_size = AES::KeySize::AES_256; break;
            default: throw std::runtime_error("Invalid AES key size");
        }
    }
    
    void updateByteArrays() {
        // For symmetric encryption, both public and private key are the same
        privateKey = symmetric_key;
        publicKey = symmetric_key;
    }
};

/**
 * @brief AES Key Generator
 */
class AESKeyGenerator : public KeyGenerator {
public:
    KeyPair generateKeyPair(size_t keySize) override {
        AESKeyPair keyPair(keySize);
        
        // Determine the AES key size enum
        AES::KeySize aesKeySize;
        switch (keySize) {
            case 128: aesKeySize = AES::KeySize::AES_128; break;
            case 192: aesKeySize = AES::KeySize::AES_192; break;
            case 256: aesKeySize = AES::KeySize::AES_256; break;
            default: throw std::runtime_error("Invalid AES key size. Use 128, 192, or 256.");
        }
        
        // Generate random symmetric key
        keyPair.symmetric_key = AES::generate_key(aesKeySize);
        keyPair.updateByteArrays();
        
        return keyPair;
    }
    
    std::string getAlgorithmName() const override {
        return "AES";
    }
};

/**
 * @brief AES Encryptor/Decryptor
 */
class AESEncryptor : public Encryptor {
private:
    AES::Mode mode_;
    
public:
    AESEncryptor(AES::Mode mode = AES::Mode::CBC) : mode_(mode) {}
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& key) override {
        if (plaintext.empty()) return {};
        
        // Generate random IV for non-ECB modes
        std::vector<uint8_t> iv;
        if (mode_ != AES::Mode::ECB) {
            iv = AES::generate_iv();
        }
        
        // Encrypt the data
        auto ciphertext = AES::encrypt(plaintext, key, mode_, iv);
        
        // Prepend IV to ciphertext for non-ECB modes
        if (mode_ != AES::Mode::ECB) {
            std::vector<uint8_t> result;
            result.reserve(iv.size() + ciphertext.size());
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            return result;
        }
        
        return ciphertext;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const std::vector<uint8_t>& key) override {
        if (ciphertext.empty()) return {};
        
        std::vector<uint8_t> iv;
        std::vector<uint8_t> encrypted_data;
        
        if (mode_ != AES::Mode::ECB) {
            // Extract IV and encrypted data
            if (ciphertext.size() < AES::BLOCK_SIZE) {
                throw std::runtime_error("Ciphertext too short to contain IV");
            }
            
            iv.assign(ciphertext.begin(), ciphertext.begin() + AES::BLOCK_SIZE);
            encrypted_data.assign(ciphertext.begin() + AES::BLOCK_SIZE, ciphertext.end());
        } else {
            encrypted_data = ciphertext;
        }
        
        // Decrypt the data
        return AES::decrypt(encrypted_data, key, mode_, iv);
    }
    
    std::string getAlgorithmName() const override {
        switch (mode_) {
            case AES::Mode::ECB: return "AES-ECB";
            case AES::Mode::CBC: return "AES-CBC";
            case AES::Mode::CTR: return "AES-CTR";
            case AES::Mode::GCM: return "AES-GCM";
            default: return "AES";
        }
    }
    
    void setMode(AES::Mode mode) { mode_ = mode; }
    AES::Mode getMode() const { return mode_; }
};

} // namespace crypto
} // namespace lockey
