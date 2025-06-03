#pragma once

#include "algorithms.hpp"
#include <random>
#include <cstring>

namespace lockey {
namespace crypto {

// AES inline implementations

inline void AES::set_key(const std::vector<uint8_t>& key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Invalid AES key size");
    }
    
    key_ = key;
    key_size_ = key.size();
    
    // Initialize round keys
    expand_key();
}

inline std::vector<uint8_t> AES::encrypt_block(const std::vector<uint8_t>& plaintext) const {
    if (plaintext.size() != BLOCK_SIZE) {
        throw std::runtime_error("Invalid block size for AES");
    }
    
    std::vector<uint8_t> state = plaintext;
    
    // Initial round
    add_round_key(state, 0);
    
    // Main rounds
    int rounds = (key_size_ == 16) ? 10 : (key_size_ == 24) ? 12 : 14;
    for (int round = 1; round < rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round);
    }
    
    // Final round
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rounds);
    
    return state;
}

inline std::vector<uint8_t> AES::decrypt_block(const std::vector<uint8_t>& ciphertext) const {
    if (ciphertext.size() != BLOCK_SIZE) {
        throw std::runtime_error("Invalid block size for AES");
    }
    
    std::vector<uint8_t> state = ciphertext;
    
    int rounds = (key_size_ == 16) ? 10 : (key_size_ == 24) ? 12 : 14;
    
    // Initial round
    add_round_key(state, rounds);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    
    // Main rounds
    for (int round = rounds - 1; round >= 1; round--) {
        add_round_key(state, round);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    
    // Final round
    add_round_key(state, 0);
    
    return state;
}

inline void AES::expand_key() {
    int rounds = (key_size_ == 16) ? 10 : (key_size_ == 24) ? 12 : 14;
    round_keys_.resize((rounds + 1) * 16);
    
    // Copy original key
    std::copy(key_.begin(), key_.end(), round_keys_.begin());
    
    int bytes_generated = key_size_;
    int rcon_iteration = 1;
    
    while (bytes_generated < (rounds + 1) * 16) {
        // Take last 4 bytes
        std::array<uint8_t, 4> temp;
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys_[bytes_generated - 4 + i];
        }
        
        if (bytes_generated % key_size_ == 0) {
            // Rotate and substitute
            uint8_t k = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[rcon_iteration++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[k];
        } else if (key_size_ == 32 && bytes_generated % key_size_ == 16) {
            // Additional transformation for AES-256
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
        }
        
        // XOR with bytes from key_size positions back
        for (int i = 0; i < 4; i++) {
            round_keys_[bytes_generated] = round_keys_[bytes_generated - key_size_] ^ temp[i];
            bytes_generated++;
        }
    }
}

inline void AES::add_round_key(std::vector<uint8_t>& state, int round) const {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_keys_[round * 16 + i];
    }
}

inline void AES::sub_bytes(std::vector<uint8_t>& state) const {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

inline void AES::inv_sub_bytes(std::vector<uint8_t>& state) const {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

inline void AES::shift_rows(std::vector<uint8_t>& state) const {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

inline void AES::inv_shift_rows(std::vector<uint8_t>& state) const {
    uint8_t temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

inline void AES::mix_columns(std::vector<uint8_t>& state) const {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c * 4];
        uint8_t s1 = state[c * 4 + 1];
        uint8_t s2 = state[c * 4 + 2];
        uint8_t s3 = state[c * 4 + 3];
        
        state[c * 4] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[c * 4 + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[c * 4 + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[c * 4 + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

inline void AES::inv_mix_columns(std::vector<uint8_t>& state) const {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c * 4];
        uint8_t s1 = state[c * 4 + 1];
        uint8_t s2 = state[c * 4 + 2];
        uint8_t s3 = state[c * 4 + 3];
        
        state[c * 4] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[c * 4 + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[c * 4 + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[c * 4 + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

inline uint8_t AES::gf_mul(uint8_t a, uint8_t b) const {
    uint8_t result = 0;
    uint8_t temp = b;
    
    for (int i = 0; i < 8; i++) {
        if (a & 1) {
            result ^= temp;
        }
        bool high_bit = temp & 0x80;
        temp <<= 1;
        if (high_bit) {
            temp ^= 0x1b; // AES irreducible polynomial
        }
        a >>= 1;
    }
    
    return result;
}

// AES S-box and inverse S-box
const std::array<uint8_t, 256> AES::sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x01, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d,
    0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28,
    0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const std::array<uint8_t, 256> AES::inv_sbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const std::array<uint8_t, 11> AES::rcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// AES-GCM inline implementations

inline std::vector<uint8_t> AES_GCM::encrypt(const std::vector<uint8_t>& plaintext,
                                            const std::vector<uint8_t>& iv,
                                            const std::vector<uint8_t>& aad) {
    if (iv.empty()) {
        throw std::runtime_error("IV cannot be empty for AES-GCM");
    }
    
    // Calculate H = AES_K(0^128)
    std::vector<uint8_t> zero_block(16, 0);
    auto h_bytes = aes_.encrypt_block(zero_block);
    std::array<uint8_t, 16> h;
    std::copy(h_bytes.begin(), h_bytes.end(), h.begin());
    
    // Calculate J0
    std::array<uint8_t, 16> j0;
    if (iv.size() == 12) {
        std::copy(iv.begin(), iv.end(), j0.begin());
        j0[15] = 1;
    } else {
        // Use GHASH for longer IVs
        auto iv_padded = iv;
        while (iv_padded.size() % 16 != 0) {
            iv_padded.push_back(0);
        }
        j0 = ghash(iv_padded, h);
    }
    
    // Encrypt plaintext using CTR mode
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size());
    
    auto counter = j0;
    counter = gcm_ctr_inc(counter);
    
    for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
        auto keystream_block = aes_.encrypt_block(std::vector<uint8_t>(counter.begin(), counter.end()));
        
        size_t block_size = std::min(BLOCK_SIZE, plaintext.size() - i);
        for (size_t j = 0; j < block_size; j++) {
            ciphertext.push_back(plaintext[i + j] ^ keystream_block[j]);
        }
        
        counter = gcm_ctr_inc(counter);
    }
    
    // Calculate authentication tag
    auto auth_tag = gcm_auth(ciphertext, aad, h, j0);
    
    // Append tag to ciphertext
    ciphertext.insert(ciphertext.end(), auth_tag.begin(), auth_tag.end());
    
    return ciphertext;
}

inline std::vector<uint8_t> AES_GCM::decrypt(const std::vector<uint8_t>& ciphertext,
                                            const std::vector<uint8_t>& iv,
                                            const std::vector<uint8_t>& aad) {
    if (ciphertext.size() < TAG_SIZE) {
        throw std::runtime_error("Ciphertext too short for AES-GCM");
    }
    
    // Extract ciphertext and tag
    size_t ct_len = ciphertext.size() - TAG_SIZE;
    std::vector<uint8_t> ct(ciphertext.begin(), ciphertext.begin() + ct_len);
    std::array<uint8_t, 16> received_tag;
    std::copy(ciphertext.begin() + ct_len, ciphertext.end(), received_tag.begin());
    
    // Calculate H
    std::vector<uint8_t> zero_block(16, 0);
    auto h_bytes = aes_.encrypt_block(zero_block);
    std::array<uint8_t, 16> h;
    std::copy(h_bytes.begin(), h_bytes.end(), h.begin());
    
    // Calculate J0
    std::array<uint8_t, 16> j0;
    if (iv.size() == 12) {
        std::copy(iv.begin(), iv.end(), j0.begin());
        j0[15] = 1;
    } else {
        auto iv_padded = iv;
        while (iv_padded.size() % 16 != 0) {
            iv_padded.push_back(0);
        }
        j0 = ghash(iv_padded, h);
    }
    
    // Verify authentication tag
    auto expected_tag = gcm_auth(ct, aad, h, j0);
    if (received_tag != expected_tag) {
        throw std::runtime_error("Authentication tag verification failed");
    }
    
    // Decrypt ciphertext
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ct.size());
    
    auto counter = j0;
    counter = gcm_ctr_inc(counter);
    
    for (size_t i = 0; i < ct.size(); i += BLOCK_SIZE) {
        auto keystream_block = aes_.encrypt_block(std::vector<uint8_t>(counter.begin(), counter.end()));
        
        size_t block_size = std::min(BLOCK_SIZE, ct.size() - i);
        for (size_t j = 0; j < block_size; j++) {
            plaintext.push_back(ct[i + j] ^ keystream_block[j]);
        }
        
        counter = gcm_ctr_inc(counter);
    }
    
    return plaintext;
}

inline std::array<uint8_t, 16> AES_GCM::ghash(const std::vector<uint8_t>& data,
                                              const std::array<uint8_t, 16>& h) const {
    std::array<uint8_t, 16> result = {0};
    
    for (size_t i = 0; i < data.size(); i += 16) {
        // XOR with current block
        for (size_t j = 0; j < 16 && i + j < data.size(); j++) {
            result[j] ^= data[i + j];
        }
        
        // Multiply by H in GF(2^128)
        gf_mul_128(result, h);
    }
    
    return result;
}

inline std::array<uint8_t, 16> AES_GCM::gcm_auth(const std::vector<uint8_t>& ciphertext,
                                                 const std::vector<uint8_t>& aad,
                                                 const std::array<uint8_t, 16>& h,
                                                 const std::array<uint8_t, 16>& j0) const {
    // Prepare data for GHASH: AAD || 0* || C || 0* || [len(A)]_64 || [len(C)]_64
    std::vector<uint8_t> ghash_input;
    
    // Add AAD with padding
    ghash_input.insert(ghash_input.end(), aad.begin(), aad.end());
    while (ghash_input.size() % 16 != 0) {
        ghash_input.push_back(0);
    }
    
    // Add ciphertext with padding
    ghash_input.insert(ghash_input.end(), ciphertext.begin(), ciphertext.end());
    while (ghash_input.size() % 16 != 0) {
        ghash_input.push_back(0);
    }
    
    // Add lengths
    uint64_t aad_bits = aad.size() * 8;
    uint64_t ct_bits = ciphertext.size() * 8;
    
    for (int i = 7; i >= 0; i--) {
        ghash_input.push_back(static_cast<uint8_t>((aad_bits >> (i * 8)) & 0xFF));
    }
    for (int i = 7; i >= 0; i--) {
        ghash_input.push_back(static_cast<uint8_t>((ct_bits >> (i * 8)) & 0xFF));
    }
    
    // Calculate GHASH
    auto ghash_result = ghash(ghash_input, h);
    
    // XOR with encrypted J0
    auto j0_encrypted = aes_.encrypt_block(std::vector<uint8_t>(j0.begin(), j0.end()));
    for (size_t i = 0; i < 16; i++) {
        ghash_result[i] ^= j0_encrypted[i];
    }
    
    return ghash_result;
}

inline std::array<uint8_t, 16> AES_GCM::gcm_ctr_inc(const std::array<uint8_t, 16>& block) const {
    std::array<uint8_t, 16> result = block;
    
    // Increment the rightmost 32 bits as a big-endian integer
    uint32_t counter = (static_cast<uint32_t>(result[12]) << 24) |
                      (static_cast<uint32_t>(result[13]) << 16) |
                      (static_cast<uint32_t>(result[14]) << 8) |
                      static_cast<uint32_t>(result[15]);
    
    counter++;
    
    result[12] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    result[13] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    result[14] = static_cast<uint8_t>((counter >> 8) & 0xFF);
    result[15] = static_cast<uint8_t>(counter & 0xFF);
    
    return result;
}

inline void AES_GCM::gf_mul_128(std::array<uint8_t, 16>& x, const std::array<uint8_t, 16>& y) const {
    std::array<uint8_t, 16> result = {0};
    std::array<uint8_t, 16> temp = x;
    
    for (int i = 0; i < 128; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        
        if ((y[byte_idx] >> bit_idx) & 1) {
            for (int j = 0; j < 16; j++) {
                result[j] ^= temp[j];
            }
        }
        
        // Shift temp right by 1 bit
        bool carry = false;
        for (int j = 0; j < 16; j++) {
            bool next_carry = temp[j] & 1;
            temp[j] >>= 1;
            if (carry) {
                temp[j] |= 0x80;
            }
            carry = next_carry;
        }
        
        // If the rightmost bit was 1, XOR with the reduction polynomial
        if (carry) {
            temp[0] ^= 0xE1;
        }
    }
    
    x = result;
}

// ChaCha20 inline implementations

inline void ChaCha20::set_key(const std::vector<uint8_t>& key) {
    if (key.size() != 32) {
        throw std::runtime_error("ChaCha20 requires a 32-byte key");
    }
    key_ = key;
}

inline std::vector<uint8_t> ChaCha20::encrypt(const std::vector<uint8_t>& plaintext,
                                             const std::vector<uint8_t>& nonce) {
    if (nonce.size() != 12) {
        throw std::runtime_error("ChaCha20 requires a 12-byte nonce");
    }
    
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size());
    
    uint32_t counter = 0;
    for (size_t i = 0; i < plaintext.size(); i += 64) {
        auto keystream = generate_keystream(counter++, nonce);
        
        size_t block_size = std::min(static_cast<size_t>(64), plaintext.size() - i);
        for (size_t j = 0; j < block_size; j++) {
            ciphertext.push_back(plaintext[i + j] ^ keystream[j]);
        }
    }
    
    return ciphertext;
}

inline std::vector<uint8_t> ChaCha20::decrypt(const std::vector<uint8_t>& ciphertext,
                                             const std::vector<uint8_t>& nonce) {
    // ChaCha20 is symmetric
    return encrypt(ciphertext, nonce);
}

inline std::array<uint8_t, 64> ChaCha20::generate_keystream(uint32_t counter, const std::vector<uint8_t>& nonce) const {
    std::array<uint32_t, 16> state;
    
    // Initialize state
    state[0] = 0x61707865; // "expa"
    state[1] = 0x3320646e; // "nd 3"
    state[2] = 0x79622d32; // "2-by"
    state[3] = 0x6b206574; // "te k"
    
    // Key (8 words)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = (static_cast<uint32_t>(key_[i * 4]) |
                       (static_cast<uint32_t>(key_[i * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(key_[i * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(key_[i * 4 + 3]) << 24));
    }
    
    // Counter
    state[12] = counter;
    
    // Nonce (3 words)
    for (int i = 0; i < 3; i++) {
        state[13 + i] = (static_cast<uint32_t>(nonce[i * 4]) |
                        (static_cast<uint32_t>(nonce[i * 4 + 1]) << 8) |
                        (static_cast<uint32_t>(nonce[i * 4 + 2]) << 16) |
                        (static_cast<uint32_t>(nonce[i * 4 + 3]) << 24));
    }
    
    // Perform 20 rounds
    std::array<uint32_t, 16> working_state = state;
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarter_round(working_state, 0, 4, 8, 12);
        quarter_round(working_state, 1, 5, 9, 13);
        quarter_round(working_state, 2, 6, 10, 14);
        quarter_round(working_state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(working_state, 0, 5, 10, 15);
        quarter_round(working_state, 1, 6, 11, 12);
        quarter_round(working_state, 2, 7, 8, 13);
        quarter_round(working_state, 3, 4, 9, 14);
    }
    
    // Add original state
    for (int i = 0; i < 16; i++) {
        working_state[i] += state[i];
    }
    
    // Convert to bytes
    std::array<uint8_t, 64> keystream;
    for (int i = 0; i < 16; i++) {
        keystream[i * 4] = static_cast<uint8_t>(working_state[i] & 0xFF);
        keystream[i * 4 + 1] = static_cast<uint8_t>((working_state[i] >> 8) & 0xFF);
        keystream[i * 4 + 2] = static_cast<uint8_t>((working_state[i] >> 16) & 0xFF);
        keystream[i * 4 + 3] = static_cast<uint8_t>((working_state[i] >> 24) & 0xFF);
    }
    
    return keystream;
}

inline void ChaCha20::quarter_round(std::array<uint32_t, 16>& state, int a, int b, int c, int d) const {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotl(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotl(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotl(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotl(state[b], 7);
}

inline uint32_t ChaCha20::rotl(uint32_t value, int shift) const {
    return (value << shift) | (value >> (32 - shift));
}

} // namespace crypto
} // namespace lockey
