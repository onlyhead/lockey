#pragma once
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>

namespace lockey {

class SHA256 {
private:
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static constexpr uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    static constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static constexpr uint32_t sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static constexpr uint32_t sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static constexpr uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static constexpr uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    static void processBlock(const uint8_t* block, uint32_t* H) {
        uint32_t W[64];
        
        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        
        for (int i = 16; i < 64; i++) {
            W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
        }
        
        // Initialize working variables
        uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
        uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
        
        // Main compression loop
        for (int i = 0; i < 64; i++) {
            uint32_t T1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
            uint32_t T2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        
        // Add compressed chunk to current hash value
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

public:
    static void hash(uint8_t* output, const uint8_t* input, size_t inputLen) {
        // Initial hash values
        uint32_t H[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        
        // Process input in 512-bit chunks
        size_t numBlocks = inputLen / 64;
        
        for (size_t i = 0; i < numBlocks; i++) {
            processBlock(input + i * 64, H);
        }
        
        // Handle padding
        uint8_t lastBlock[128] = {0}; // Space for potential two blocks
        size_t remaining = inputLen % 64;
        
        // Copy remaining bytes
        if (remaining > 0) {
            std::memcpy(lastBlock, input + numBlocks * 64, remaining);
        }
        
        // Append '1' bit (0x80)
        lastBlock[remaining] = 0x80;
        
        // If not enough space for length, use two blocks
        size_t lengthPos = (remaining < 56) ? 56 : 120;
        
        // Append length in bits as 64-bit big-endian
        uint64_t bitLength = inputLen * 8;
        for (int i = 7; i >= 0; i--) {
            lastBlock[lengthPos + i] = static_cast<uint8_t>(bitLength & 0xFF);
            bitLength >>= 8;
        }
        
        // Process final block(s)
        processBlock(lastBlock, H);
        if (lengthPos == 120) {
            processBlock(lastBlock + 64, H);
        }
        
        // Produce final hash value (big-endian)
        for (int i = 0; i < 8; i++) {
            output[i * 4] = static_cast<uint8_t>(H[i] >> 24);
            output[i * 4 + 1] = static_cast<uint8_t>(H[i] >> 16);
            output[i * 4 + 2] = static_cast<uint8_t>(H[i] >> 8);
            output[i * 4 + 3] = static_cast<uint8_t>(H[i]);
        }
    }
    
    // Convenience function that returns a vector
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> output(32); // SHA-256 produces 32 bytes
        hash(output.data(), input.data(), input.size());
        return output;
    }
};

// Convenience function
inline void sha256(uint8_t* output, const uint8_t* input, size_t inputLen) {
    SHA256::hash(output, input, inputLen);
}

} // namespace lockey
