#pragma once

#include "algorithm/blake2s.hpp"
#include "algorithm/bigint.hpp"
#include "algorithm/rsa.hpp"
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <stdexcept>

namespace lockey {

// High-level encryption/decryption interface
class Lockey {
public:
    // Key generation
    static RSAKeyPair generateKeyPair(size_t keySize = 2048) {
        return RSA::generateKey(keySize);
    }
    
    // String-based encryption/decryption
    static std::string encrypt(const std::string& plaintext, const BigInt& e, const BigInt& n) {
        std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
        return encryptBytes(data, e, n);
    }
    
    static std::string decrypt(const std::string& ciphertext, const BigInt& d, const BigInt& n) {
        std::vector<uint8_t> decryptedBytes = decryptToBytes(ciphertext, d, n);
        return std::string(decryptedBytes.begin(), decryptedBytes.end());
    }
    
    // Byte-based encryption/decryption  
    static std::string encryptBytes(const std::vector<uint8_t>& data, const BigInt& e, const BigInt& n) {
        // Simple approach: convert data to BigInt and encrypt directly
        // Note: This is not secure for production use - needs proper padding
        
        if (data.empty()) return "";
        
        BigInt message(data);
        
        // Ensure message is smaller than n
        if (message >= n) {
            throw std::runtime_error("Message too large for key size");
        }
        
        BigInt encrypted = RSA::encrypt(message, e, n);
        return bigIntToHex(encrypted);
    }
    
    static std::vector<uint8_t> decryptToBytes(const std::string& hexCiphertext, const BigInt& d, const BigInt& n) {
        if (hexCiphertext.empty()) return {};
        
        BigInt encrypted(hexToBytes(hexCiphertext));
        BigInt decrypted = RSA::decrypt(encrypted, d, n);
        
        return decrypted.toBytes();
    }
    
    // Digital signatures
    static std::string sign(const std::string& message, const BigInt& d, const BigInt& n) {
        std::vector<uint8_t> msgBytes(message.begin(), message.end());
        BigInt signature = RSA::sign(msgBytes, d, n);
        return bigIntToHex(signature);
    }
    
    static bool verify(const std::string& message, const std::string& hexSignature, const BigInt& e, const BigInt& n) {
        std::vector<uint8_t> msgBytes(message.begin(), message.end());
        BigInt signature(hexToBytes(hexSignature));
        return RSA::verify(msgBytes, signature, e, n);
    }
    
    // Hash function access
    static std::string hash(const std::string& input) {
        std::vector<uint8_t> inputBytes(input.begin(), input.end());
        return hashBytes(inputBytes);
    }
    
    static std::string hashBytes(const std::vector<uint8_t>& input) {
        uint8_t hash[32];
        blake2s(hash, input.data(), input.size());
        return bytesToHex(std::vector<uint8_t>(hash, hash + 32));
    }
    
    // Key serialization helpers
    static std::string keyToString(const RSAKeyPair& keyPair) {
        return "n=" + bigIntToHex(keyPair.n) + ",e=" + bigIntToHex(keyPair.e) + ",d=" + bigIntToHex(keyPair.d);
    }
    
    static RSAKeyPair keyFromString(const std::string& keyStr) {
        RSAKeyPair result;
        
        size_t nPos = keyStr.find("n=");
        size_t ePos = keyStr.find(",e=");
        size_t dPos = keyStr.find(",d=");
        
        if (nPos != std::string::npos && ePos != std::string::npos && dPos != std::string::npos) {
            std::string nHex = keyStr.substr(nPos + 2, ePos - nPos - 2);
            std::string eHex = keyStr.substr(ePos + 3, dPos - ePos - 3);
            std::string dHex = keyStr.substr(dPos + 3);
            
            result.n = BigInt(hexToBytes(nHex));
            result.e = BigInt(hexToBytes(eHex));
            result.d = BigInt(hexToBytes(dHex));
        }
        
        return result;
    }
    
    // Utility functions
    static std::string bigIntToHex(const BigInt& num) {
        if (num.isZero()) return "0";
        
        std::string result;
        BigInt temp = num;
        BigInt sixteen(16);
        
        while (!temp.isZero()) {
            auto dm = BigInt::divMod(temp, sixteen);
            uint32_t digit = dm.second.isZero() ? 0 : dm.second.getLowLimb();
            result = "0123456789abcdef"[digit] + result;
            temp = dm.first;
        }
        
        return result;
    }
    
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> result;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtoul(byteStr.c_str(), nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }
    
    static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        std::string result;
        for (uint8_t byte : bytes) {
            result += "0123456789abcdef"[byte >> 4];
            result += "0123456789abcdef"[byte & 0x0F];
        }
        return result;
    }
};

} // namespace lockey