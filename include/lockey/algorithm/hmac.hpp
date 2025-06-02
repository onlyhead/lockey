#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

namespace lockey {

template<typename HashFunction>
class HMAC {
private:
    static constexpr size_t BLOCK_SIZE = 64; // 512 bits for most hash functions
    
public:
    static std::vector<uint8_t> compute(const std::vector<uint8_t>& key, 
                                       const std::vector<uint8_t>& message,
                                       size_t hashSize) {
        std::vector<uint8_t> processedKey = key;
        
        // If key is longer than block size, hash it
        if (processedKey.size() > BLOCK_SIZE) {
            uint8_t hashedKey[hashSize];
            HashFunction::hash(hashedKey, processedKey.data(), processedKey.size());
            processedKey.assign(hashedKey, hashedKey + hashSize);
        }
        
        // Pad key to block size
        if (processedKey.size() < BLOCK_SIZE) {
            processedKey.resize(BLOCK_SIZE, 0);
        }
        
        // Create inner and outer padded keys
        std::vector<uint8_t> innerKey(BLOCK_SIZE);
        std::vector<uint8_t> outerKey(BLOCK_SIZE);
        
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            innerKey[i] = processedKey[i] ^ 0x36; // ipad
            outerKey[i] = processedKey[i] ^ 0x5C; // opad
        }
        
        // Compute inner hash: H(K ⊕ ipad || message)
        std::vector<uint8_t> innerInput;
        innerInput.reserve(BLOCK_SIZE + message.size());
        innerInput.insert(innerInput.end(), innerKey.begin(), innerKey.end());
        innerInput.insert(innerInput.end(), message.begin(), message.end());
        
        uint8_t innerHash[hashSize];
        HashFunction::hash(innerHash, innerInput.data(), innerInput.size());
        
        // Compute outer hash: H(K ⊕ opad || H(K ⊕ ipad || message))
        std::vector<uint8_t> outerInput;
        outerInput.reserve(BLOCK_SIZE + hashSize);
        outerInput.insert(outerInput.end(), outerKey.begin(), outerKey.end());
        outerInput.insert(outerInput.end(), innerHash, innerHash + hashSize);
        
        uint8_t finalHash[hashSize];
        HashFunction::hash(finalHash, outerInput.data(), outerInput.size());
        
        return std::vector<uint8_t>(finalHash, finalHash + hashSize);
    }
    
    static std::vector<uint8_t> compute(const std::string& key, 
                                       const std::string& message,
                                       size_t hashSize) {
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        std::vector<uint8_t> messageBytes(message.begin(), message.end());
        return compute(keyBytes, messageBytes, hashSize);
    }
};

} // namespace lockey
