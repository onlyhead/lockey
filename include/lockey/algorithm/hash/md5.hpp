#pragma once
#include <cstdint>
#include <cstring>

namespace lockey {

class MD5 {
private:
    static constexpr uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }

    static constexpr uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }

    static constexpr uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }

    static constexpr uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
        return y ^ (x | ~z);
    }

    static void processBlock(const uint8_t* block, uint32_t* hash) {
        // Convert block to little-endian words
        uint32_t X[16];
        for (int i = 0; i < 16; i++) {
            X[i] = static_cast<uint32_t>(block[i * 4]) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
        }

        uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3];

        // Round 1
        constexpr uint32_t S1[4] = {7, 12, 17, 22};
        constexpr uint32_t T1[16] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
        };

        for (int i = 0; i < 16; i++) {
            uint32_t temp = A + F(B, C, D) + X[i] + T1[i];
            temp = rotl(temp, S1[i % 4]);
            temp += B;
            A = D; D = C; C = B; B = temp;
        }

        // Round 2
        constexpr uint32_t S2[4] = {5, 9, 14, 20};
        constexpr uint32_t T2[16] = {
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
        };

        for (int i = 0; i < 16; i++) {
            uint32_t temp = A + G(B, C, D) + X[(5 * i + 1) % 16] + T2[i];
            temp = rotl(temp, S2[i % 4]);
            temp += B;
            A = D; D = C; C = B; B = temp;
        }

        // Round 3
        constexpr uint32_t S3[4] = {4, 11, 16, 23};
        constexpr uint32_t T3[16] = {
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
        };

        for (int i = 0; i < 16; i++) {
            uint32_t temp = A + H(B, C, D) + X[(3 * i + 5) % 16] + T3[i];
            temp = rotl(temp, S3[i % 4]);
            temp += B;
            A = D; D = C; C = B; B = temp;
        }

        // Round 4
        constexpr uint32_t S4[4] = {6, 10, 15, 21};
        constexpr uint32_t T4[16] = {
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        for (int i = 0; i < 16; i++) {
            uint32_t temp = A + I(B, C, D) + X[(7 * i) % 16] + T4[i];
            temp = rotl(temp, S4[i % 4]);
            temp += B;
            A = D; D = C; C = B; B = temp;
        }

        // Add this chunk's hash to result so far
        hash[0] += A; hash[1] += B; hash[2] += C; hash[3] += D;
    }

public:
    static void hash(uint8_t* output, const uint8_t* input, size_t inputLen) {
        // Initial hash values
        uint32_t hash[4] = {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        };

        // Process input in 512-bit chunks
        size_t numBlocks = inputLen / 64;
        
        for (size_t i = 0; i < numBlocks; i++) {
            processBlock(input + i * 64, hash);
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

        // Append length in bits as 64-bit little-endian
        uint64_t bitLength = inputLen * 8;
        for (int i = 0; i < 8; i++) {
            lastBlock[lengthPos + i] = static_cast<uint8_t>(bitLength & 0xFF);
            bitLength >>= 8;
        }

        // Process final block(s)
        processBlock(lastBlock, hash);
        if (lengthPos == 120) {
            processBlock(lastBlock + 64, hash);
        }

        // Produce final hash value (little-endian)
        for (int i = 0; i < 4; i++) {
            output[i * 4] = static_cast<uint8_t>(hash[i]);
            output[i * 4 + 1] = static_cast<uint8_t>(hash[i] >> 8);
            output[i * 4 + 2] = static_cast<uint8_t>(hash[i] >> 16);
            output[i * 4 + 3] = static_cast<uint8_t>(hash[i] >> 24);
        }
    }
};

// Convenience function
inline void md5(uint8_t* output, const uint8_t* input, size_t inputLen) {
    MD5::hash(output, input, inputLen);
}

} // namespace lockey
