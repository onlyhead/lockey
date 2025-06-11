#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <cstring>
#include "../utils/common.hpp"

namespace lockey {
namespace hash {

/**
 * @brief Base hash class interface
 */
class HashBase {
public:
    virtual ~HashBase() = default;
    virtual void init() = 0;
    virtual void update(const uint8_t* data, size_t length) = 0;
    virtual void finalize(uint8_t* output) = 0;
    virtual size_t digest_size() const = 0;
    virtual size_t block_size() const = 0;
};

/**
 * @brief SHA-256 implementation
 */
class SHA256 : public HashBase {
private:
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t BLOCK_SIZE = 64;
    
    std::array<uint32_t, 8> state_;
    std::array<uint8_t, BLOCK_SIZE> buffer_;
    uint64_t total_length_;
    size_t buffer_length_;

    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    void process_block();
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

public:
    SHA256() { init(); }
    
    void init() override {
        state_ = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        total_length_ = 0;
        buffer_length_ = 0;
    }
    
    void update(const uint8_t* data, size_t length) override;
    void finalize(uint8_t* output) override;
    size_t digest_size() const override { return DIGEST_SIZE; }
    size_t block_size() const override { return BLOCK_SIZE; }
    
    // Convenience method to compute hash in one call
    std::vector<uint8_t> compute(const std::vector<uint8_t>& data) {
        init();
        update(data.data(), data.size());
        std::vector<uint8_t> result(DIGEST_SIZE);
        finalize(result.data());
        return result;
    }
};

/**
 * @brief SHA-384 implementation
 */
class SHA384 : public HashBase {
private:
    static constexpr size_t DIGEST_SIZE = 48;
    static constexpr size_t BLOCK_SIZE = 128;
    
    std::array<uint64_t, 8> state_;
    std::array<uint8_t, BLOCK_SIZE> buffer_;
    uint64_t total_length_;
    size_t buffer_length_;

    static constexpr std::array<uint64_t, 80> K = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    void process_block();
    static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
    static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
    static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint64_t sigma0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    static uint64_t sigma1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
    static uint64_t gamma0(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
    static uint64_t gamma1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

public:
    SHA384() { init(); }
    
    void init() override {
        state_ = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
        };
        total_length_ = 0;
        buffer_length_ = 0;
    }
    
    void update(const uint8_t* data, size_t length) override;
    void finalize(uint8_t* output) override;
    size_t digest_size() const override { return DIGEST_SIZE; }
    size_t block_size() const override { return BLOCK_SIZE; }
    
    // Convenience method to compute hash in one call
    std::vector<uint8_t> compute(const std::vector<uint8_t>& data) {
        init();
        update(data.data(), data.size());
        std::vector<uint8_t> result(DIGEST_SIZE);
        finalize(result.data());
        return result;
    }
};

/**
 * @brief SHA-512 implementation
 */
class SHA512 : public HashBase {
private:
    static constexpr size_t DIGEST_SIZE = 64;
    static constexpr size_t BLOCK_SIZE = 128;
    
    std::array<uint64_t, 8> state_;
    std::array<uint8_t, BLOCK_SIZE> buffer_;
    uint64_t total_length_;
    size_t buffer_length_;

    static constexpr std::array<uint64_t, 80> K = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    void process_block();
    static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
    static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
    static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint64_t sigma0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    static uint64_t sigma1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
    static uint64_t gamma0(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
    static uint64_t gamma1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

public:
    SHA512() { init(); }
    
    void init() override {
        state_ = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        total_length_ = 0;
        buffer_length_ = 0;
    }
    
    void update(const uint8_t* data, size_t length) override;
    void finalize(uint8_t* output) override;
    size_t digest_size() const override { return DIGEST_SIZE; }
    size_t block_size() const override { return BLOCK_SIZE; }
    
    // Convenience method to compute hash in one call
    std::vector<uint8_t> compute(const std::vector<uint8_t>& data) {
        init();
        update(data.data(), data.size());
        std::vector<uint8_t> result(DIGEST_SIZE);
        finalize(result.data());
        return result;
    }
};

/**
 * @brief BLAKE2b implementation
 */
class BLAKE2b : public HashBase {
private:
    static constexpr size_t DIGEST_SIZE = 64;
    static constexpr size_t BLOCK_SIZE = 128;
    static constexpr size_t MAX_KEY_SIZE = 64;
    
    std::array<uint64_t, 8> state_;
    std::array<uint8_t, BLOCK_SIZE> buffer_;
    size_t buffer_length_;
    uint64_t total_length_;
    size_t digest_length_;
    
    // BLAKE2b initialization vectors
    static constexpr std::array<uint64_t, 8> IV = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    
    // BLAKE2b sigma permutations
    static constexpr std::array<std::array<int, 16>, 12> SIGMA = {{
        {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
        {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
        {{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}},
        {{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}},
        {{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}},
        {{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}},
        {{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}},
        {{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}},
        {{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}},
        {{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}},
        {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
        {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}}
    }};
    
    void process_block(bool is_final = false);
    static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
    
    void blake2b_mix(std::array<uint64_t, 16>& v, int a, int b, int c, int d, uint64_t x, uint64_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = rotr(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = rotr(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = rotr(v[b] ^ v[c], 63);
    }

public:
    BLAKE2b(size_t digest_size = DIGEST_SIZE) : digest_length_(digest_size) {
        if (digest_size == 0 || digest_size > DIGEST_SIZE) {
            throw std::runtime_error("Invalid BLAKE2b digest size");
        }
        init();
    }
    
    void init() override {
        state_ = IV;
        // XOR first state word with parameter block
        state_[0] ^= 0x01010000ULL ^ (static_cast<uint64_t>(digest_length_) << 16);
        
        buffer_length_ = 0;
        total_length_ = 0;
    }
    
    void update(const uint8_t* data, size_t length) override;
    void finalize(uint8_t* output) override;
    size_t digest_size() const override { return digest_length_; }
    size_t block_size() const override { return BLOCK_SIZE; }
    
    // Convenience method to compute hash in one call
    std::vector<uint8_t> compute(const std::vector<uint8_t>& data) {
        init();
        update(data.data(), data.size());
        std::vector<uint8_t> result(digest_length_);
        finalize(result.data());
        return result;
    }
};

/**
 * @brief HMAC implementation
 */
template<typename HashFunction>
class HMAC {
private:
    HashFunction hash_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> ipad_;
    std::vector<uint8_t> opad_;

public:
    explicit HMAC(const std::vector<uint8_t>& key) {
        set_key(key);
    }

    void set_key(const std::vector<uint8_t>& key) {
        key_ = key;
        size_t block_size = hash_.block_size();
        
        // Process key
        std::vector<uint8_t> processed_key;
        if (key.size() > block_size) {
            // Hash the key if it's too long
            hash_.init();
            hash_.update(key.data(), key.size());
            processed_key.resize(hash_.digest_size());
            hash_.finalize(processed_key.data());
        } else {
            processed_key = key;
        }
        
        // Pad key to block size
        processed_key.resize(block_size, 0);
        
        // Create inner and outer padding
        ipad_.resize(block_size);
        opad_.resize(block_size);
        for (size_t i = 0; i < block_size; ++i) {
            ipad_[i] = processed_key[i] ^ 0x36;
            opad_[i] = processed_key[i] ^ 0x5c;
        }
    }

    std::vector<uint8_t> compute(const std::vector<uint8_t>& data) {
        // Inner hash: H(K XOR ipad, message)
        hash_.init();
        hash_.update(ipad_.data(), ipad_.size());
        hash_.update(data.data(), data.size());
        
        std::vector<uint8_t> inner_hash(hash_.digest_size());
        hash_.finalize(inner_hash.data());
        
        // Outer hash: H(K XOR opad, inner_hash)
        hash_.init();
        hash_.update(opad_.data(), opad_.size());
        hash_.update(inner_hash.data(), inner_hash.size());
        
        std::vector<uint8_t> result(hash_.digest_size());
        hash_.finalize(result.data());
        
        return result;
    }
};

} // namespace hash
} // namespace lockey
