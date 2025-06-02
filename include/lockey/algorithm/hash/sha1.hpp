#pragma once
#include <cstdint>
#include <cstring>

namespace lockey {

class SHA1 {
private:
    static constexpr uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr uint32_t f(int t, uint32_t b, uint32_t c, uint32_t d) {
        if (t < 20) {
            return (b & c) | (~b & d);
        } else if (t < 40) {
            return b ^ c ^ d;
        } else if (t < 60) {
            return (b & c) | (b & d) | (c & d);
        } else {
            return b ^ c ^ d;
        }
    }

    static constexpr uint32_t K(int t) {
        if (t < 20) return 0x5a827999;
        if (t < 40) return 0x6ed9eba1;
        if (t < 60) return 0x8f1bbcdc;
        return 0xca62c1d6;
    }

    static void processBlock(const uint8_t* block, uint32_t* H) {
        uint32_t W[80];
        
        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        
        for (int i = 16; i < 80; i++) {
            W[i] = rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
        }
        
        // Initialize working variables
        uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
        
        // Main compression loop
        for (int i = 0; i < 80; i++) {
            uint32_t temp = rotl(a, 5) + f(i, b, c, d) + e + W[i] + K(i);
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        
        // Add compressed chunk to current hash value
        H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
    }

public:
    static void hash(uint8_t* output, const uint8_t* input, size_t inputLen) {
        // Initial hash values
        uint32_t H[5] = {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
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
        for (int i = 0; i < 5; i++) {
            output[i * 4] = static_cast<uint8_t>(H[i] >> 24);
            output[i * 4 + 1] = static_cast<uint8_t>(H[i] >> 16);
            output[i * 4 + 2] = static_cast<uint8_t>(H[i] >> 8);
            output[i * 4 + 3] = static_cast<uint8_t>(H[i]);
        }
    }
};

// Convenience function
inline void sha1(uint8_t* output, const uint8_t* input, size_t inputLen) {
    SHA1::hash(output, input, inputLen);
}

} // namespace lockey
