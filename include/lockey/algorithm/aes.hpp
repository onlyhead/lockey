#pragma once
#include <vector>
#include <cstdint>
#include <array>
#include <random>
#include <stdexcept>
#include <algorithm>

namespace lockey {

/**
 * @brief AES (Advanced Encryption Standard) implementation
 * 
 * Supports AES-128, AES-192, and AES-256 in various modes.
 * Based on BearSSL's AES implementation.
 */
class AES {
public:
    static constexpr size_t BLOCK_SIZE = 16; // AES block size is always 16 bytes
    
    enum class KeySize {
        AES_128 = 16,
        AES_192 = 24,
        AES_256 = 32
    };
    
    enum class Mode {
        ECB,    // Electronic Codebook (not recommended for most uses)
        CBC,    // Cipher Block Chaining
        CTR,    // Counter mode
        GCM     // Galois/Counter Mode (authenticated encryption)
    };
    
    /**
     * @brief AES encryption/decryption context
     */
    class Context {
    private:
        std::array<uint32_t, 60> round_keys_; // Maximum for AES-256 (14 rounds + 1 = 15 * 4 = 60)
        KeySize key_size_;
        int num_rounds_;
        
    public:
        Context(const std::vector<uint8_t>& key);
        
        // Block-level encryption/decryption
        void encrypt_block(const uint8_t input[16], uint8_t output[16]) const;
        void decrypt_block(const uint8_t input[16], uint8_t output[16]) const;
        
        KeySize get_key_size() const { return key_size_; }
        int get_num_rounds() const { return num_rounds_; }
        
    private:
        void key_expansion(const std::vector<uint8_t>& key);
        
        // AES round functions
        void add_round_key(uint8_t state[16], const uint32_t* round_key) const;
        void sub_bytes(uint8_t state[16]) const;
        void inv_sub_bytes(uint8_t state[16]) const;
        void shift_rows(uint8_t state[16]) const;
        void inv_shift_rows(uint8_t state[16]) const;
        void mix_columns(uint8_t state[16]) const;
        void inv_mix_columns(uint8_t state[16]) const;
        
        // Helper functions
        uint8_t gf_mult(uint8_t a, uint8_t b) const;
        uint32_t sub_word(uint32_t word) const;
        uint32_t rot_word(uint32_t word) const;
    };
    
    /**
     * @brief Encrypt data using AES in specified mode
     * 
     * @param plaintext The data to encrypt
     * @param key The encryption key
     * @param mode The encryption mode
     * @param iv Initialization vector (for CBC, CTR modes)
     * @return Encrypted data
     */
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                       const std::vector<uint8_t>& key,
                                       Mode mode = Mode::CBC,
                                       const std::vector<uint8_t>& iv = {});
    
    /**
     * @brief Decrypt data using AES in specified mode
     * 
     * @param ciphertext The data to decrypt
     * @param key The decryption key
     * @param mode The decryption mode
     * @param iv Initialization vector (for CBC, CTR modes)
     * @return Decrypted data
     */
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& key,
                                       Mode mode = Mode::CBC,
                                       const std::vector<uint8_t>& iv = {});
    
    /**
     * @brief Generate a random AES key
     * 
     * @param key_size The desired key size
     * @return Random key bytes
     */
    static std::vector<uint8_t> generate_key(KeySize key_size);
    
    /**
     * @brief Generate a random initialization vector
     * 
     * @return Random 16-byte IV
     */
    static std::vector<uint8_t> generate_iv();
    
private:
    // AES S-box
    static const uint8_t s_box[256];
    static const uint8_t inv_s_box[256];
    
    // Round constants for key expansion
    static const uint32_t rcon[10];
    
    // Mode-specific encryption/decryption
    static std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& plaintext,
                                           const Context& ctx);
    static std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& ciphertext,
                                           const Context& ctx);
    
    static std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plaintext,
                                           const Context& ctx,
                                           const std::vector<uint8_t>& iv);
    static std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& ciphertext,
                                           const Context& ctx,
                                           const std::vector<uint8_t>& iv);
    
    static std::vector<uint8_t> encrypt_ctr(const std::vector<uint8_t>& plaintext,
                                           const Context& ctx,
                                           const std::vector<uint8_t>& iv);
    static std::vector<uint8_t> decrypt_ctr(const std::vector<uint8_t>& ciphertext,
                                           const Context& ctx,
                                           const std::vector<uint8_t>& iv);
    
    // Padding functions (PKCS#7)
    static std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data);
    
    // XOR operation for arrays
    static void xor_arrays(uint8_t* dest, const uint8_t* src, size_t len);
    
    // Increment counter for CTR mode
    static void increment_counter(uint8_t counter[16]);
};

// ===== Static member definitions =====
inline const uint8_t AES::s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

inline const uint8_t AES::inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

inline const uint32_t AES::rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

// ===== Implementations =====

inline AES::Context::Context(const std::vector<uint8_t>& key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::invalid_argument("Invalid AES key size. Must be 16, 24, or 32 bytes.");
    }
    
    key_size_ = static_cast<KeySize>(key.size());
    switch (key_size_) {
        case KeySize::AES_128: num_rounds_ = 10; break;
        case KeySize::AES_192: num_rounds_ = 12; break;
        case KeySize::AES_256: num_rounds_ = 14; break;
    }
    
    key_expansion(key);
}

inline void AES::Context::key_expansion(const std::vector<uint8_t>& key) {
    int key_words = static_cast<int>(key_size_) / 4;
    int total_words = 4 * (num_rounds_ + 1);
    
    // Copy initial key
    for (int i = 0; i < key_words; i++) {
        round_keys_[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
    }
    
    // Generate remaining words
    for (int i = key_words; i < total_words; i++) {
        uint32_t temp = round_keys_[i-1];
        
        if (i % key_words == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[(i / key_words) - 1];
        } else if (key_words > 6 && (i % key_words) == 4) {
            temp = sub_word(temp);
        }
        
        round_keys_[i] = round_keys_[i - key_words] ^ temp;
    }
}

inline uint32_t AES::Context::sub_word(uint32_t word) const {
    return (s_box[(word >> 24) & 0xFF] << 24) |
           (s_box[(word >> 16) & 0xFF] << 16) |
           (s_box[(word >> 8) & 0xFF] << 8) |
           s_box[word & 0xFF];
}

inline uint32_t AES::Context::rot_word(uint32_t word) const {
    return (word << 8) | (word >> 24);
}

inline void AES::Context::encrypt_block(const uint8_t input[16], uint8_t output[16]) const {
    uint8_t state[16];
    std::copy(input, input + 16, state);
    
    // Initial round
    add_round_key(state, &round_keys_[0]);
    
    // Main rounds
    for (int round = 1; round < num_rounds_; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &round_keys_[round * 4]);
    }
    
    // Final round
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys_[num_rounds_ * 4]);
    
    std::copy(state, state + 16, output);
}

inline void AES::Context::decrypt_block(const uint8_t input[16], uint8_t output[16]) const {
    uint8_t state[16];
    std::copy(input, input + 16, state);
    
    // Initial round
    add_round_key(state, &round_keys_[num_rounds_ * 4]);
    
    // Main rounds (in reverse)
    for (int round = num_rounds_ - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &round_keys_[round * 4]);
        inv_mix_columns(state);
    }
    
    // Final round
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &round_keys_[0]);
    
    std::copy(state, state + 16, output);
}

inline void AES::Context::add_round_key(uint8_t state[16], const uint32_t* round_key) const {
    for (int i = 0; i < 4; i++) {
        uint32_t key_word = round_key[i];
        state[4*i] ^= (key_word >> 24) & 0xFF;
        state[4*i+1] ^= (key_word >> 16) & 0xFF;
        state[4*i+2] ^= (key_word >> 8) & 0xFF;
        state[4*i+3] ^= key_word & 0xFF;
    }
}

inline void AES::Context::sub_bytes(uint8_t state[16]) const {
    for (int i = 0; i < 16; i++) {
        state[i] = s_box[state[i]];
    }
}

inline void AES::Context::inv_sub_bytes(uint8_t state[16]) const {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_s_box[state[i]];
    }
}

inline void AES::Context::shift_rows(uint8_t state[16]) const {
    uint8_t temp;
    // Row 1: shift left by 1
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    // Row 2: shift left by 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    // Row 3: shift left by 3 (equivalent to right by 1)
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

inline void AES::Context::inv_shift_rows(uint8_t state[16]) const {
    uint8_t temp;
    // Row 1: shift right by 1
    temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
    // Row 2: shift right by 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    // Row 3: shift right by 3 (equivalent to left by 1)
    temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
}

inline void AES::Context::mix_columns(uint8_t state[16]) const {
    for (int col = 0; col < 4; col++) {
        uint8_t a[4];
        for (int i = 0; i < 4; i++) {
            a[i] = state[col * 4 + i];
        }
        
        state[col * 4 + 0] = gf_mult(0x02, a[0]) ^ gf_mult(0x03, a[1]) ^ a[2] ^ a[3];
        state[col * 4 + 1] = a[0] ^ gf_mult(0x02, a[1]) ^ gf_mult(0x03, a[2]) ^ a[3];
        state[col * 4 + 2] = a[0] ^ a[1] ^ gf_mult(0x02, a[2]) ^ gf_mult(0x03, a[3]);
        state[col * 4 + 3] = gf_mult(0x03, a[0]) ^ a[1] ^ a[2] ^ gf_mult(0x02, a[3]);
    }
}

inline void AES::Context::inv_mix_columns(uint8_t state[16]) const {
    for (int col = 0; col < 4; col++) {
        uint8_t a[4];
        for (int i = 0; i < 4; i++) {
            a[i] = state[col * 4 + i];
        }
        
        state[col * 4 + 0] = gf_mult(0x0E, a[0]) ^ gf_mult(0x0B, a[1]) ^ gf_mult(0x0D, a[2]) ^ gf_mult(0x09, a[3]);
        state[col * 4 + 1] = gf_mult(0x09, a[0]) ^ gf_mult(0x0E, a[1]) ^ gf_mult(0x0B, a[2]) ^ gf_mult(0x0D, a[3]);
        state[col * 4 + 2] = gf_mult(0x0D, a[0]) ^ gf_mult(0x09, a[1]) ^ gf_mult(0x0E, a[2]) ^ gf_mult(0x0B, a[3]);
        state[col * 4 + 3] = gf_mult(0x0B, a[0]) ^ gf_mult(0x0D, a[1]) ^ gf_mult(0x09, a[2]) ^ gf_mult(0x0E, a[3]);
    }
}

inline uint8_t AES::Context::gf_mult(uint8_t a, uint8_t b) const {
    uint8_t result = 0;
    uint8_t hi_bit_set;
    
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; // AES irreducible polynomial
        }
        b >>= 1;
    }
    
    return result;
}

inline std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& key,
                                        Mode mode,
                                        const std::vector<uint8_t>& iv) {
    Context ctx(key);
    
    switch (mode) {
        case Mode::ECB:
            return encrypt_ecb(plaintext, ctx);
        case Mode::CBC:
            return encrypt_cbc(plaintext, ctx, iv);
        case Mode::CTR:
            return encrypt_ctr(plaintext, ctx, iv);
        default:
            throw std::invalid_argument("Unsupported AES mode");
    }
}

inline std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key,
                                        Mode mode,
                                        const std::vector<uint8_t>& iv) {
    Context ctx(key);
    
    switch (mode) {
        case Mode::ECB:
            return decrypt_ecb(ciphertext, ctx);
        case Mode::CBC:
            return decrypt_cbc(ciphertext, ctx, iv);
        case Mode::CTR:
            return decrypt_ctr(ciphertext, ctx, iv);
        default:
            throw std::invalid_argument("Unsupported AES mode");
    }
}

inline std::vector<uint8_t> AES::generate_key(KeySize key_size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    std::vector<uint8_t> key(static_cast<size_t>(key_size));
    for (auto& byte : key) {
        byte = dis(gen);
    }
    
    return key;
}

inline std::vector<uint8_t> AES::generate_iv() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    std::vector<uint8_t> iv(BLOCK_SIZE);
    for (auto& byte : iv) {
        byte = dis(gen);
    }
    
    return iv;
}

inline std::vector<uint8_t> AES::encrypt_ecb(const std::vector<uint8_t>& plaintext, const Context& ctx) {
    auto padded = add_padding(plaintext);
    std::vector<uint8_t> ciphertext(padded.size());
    
    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        ctx.encrypt_block(&padded[i], &ciphertext[i]);
    }
    
    return ciphertext;
}

inline std::vector<uint8_t> AES::decrypt_ecb(const std::vector<uint8_t>& ciphertext, const Context& ctx) {
    if (ciphertext.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("Ciphertext size must be multiple of block size");
    }
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        ctx.decrypt_block(&ciphertext[i], &plaintext[i]);
    }
    
    return remove_padding(plaintext);
}

inline std::vector<uint8_t> AES::encrypt_cbc(const std::vector<uint8_t>& plaintext,
                                            const Context& ctx,
                                            const std::vector<uint8_t>& iv) {
    if (iv.size() != BLOCK_SIZE) {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    
    auto padded = add_padding(plaintext);
    std::vector<uint8_t> ciphertext(padded.size());
    std::vector<uint8_t> prev_block = iv;
    
    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] = padded[i + j] ^ prev_block[j];
        }
        
        ctx.encrypt_block(block, &ciphertext[i]);
        prev_block.assign(&ciphertext[i], &ciphertext[i] + BLOCK_SIZE);
    }
    
    return ciphertext;
}

inline std::vector<uint8_t> AES::decrypt_cbc(const std::vector<uint8_t>& ciphertext,
                                            const Context& ctx,
                                            const std::vector<uint8_t>& iv) {
    if (iv.size() != BLOCK_SIZE) {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    
    if (ciphertext.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("Ciphertext size must be multiple of block size");
    }
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    std::vector<uint8_t> prev_block = iv;
    
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        ctx.decrypt_block(&ciphertext[i], block);
        
        for (int j = 0; j < BLOCK_SIZE; j++) {
            plaintext[i + j] = block[j] ^ prev_block[j];
        }
        
        prev_block.assign(&ciphertext[i], &ciphertext[i] + BLOCK_SIZE);
    }
    
    return remove_padding(plaintext);
}

inline std::vector<uint8_t> AES::encrypt_ctr(const std::vector<uint8_t>& plaintext,
                                            const Context& ctx,
                                            const std::vector<uint8_t>& iv) {
    if (iv.size() != BLOCK_SIZE) {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    
    std::vector<uint8_t> ciphertext(plaintext.size());
    uint8_t counter[BLOCK_SIZE];
    std::copy(iv.begin(), iv.end(), counter);
    
    for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
        uint8_t keystream[BLOCK_SIZE];
        ctx.encrypt_block(counter, keystream);
        
        size_t block_size = std::min(BLOCK_SIZE, plaintext.size() - i);
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        
        increment_counter(counter);
    }
    
    return ciphertext;
}

inline std::vector<uint8_t> AES::decrypt_ctr(const std::vector<uint8_t>& ciphertext,
                                            const Context& ctx,
                                            const std::vector<uint8_t>& iv) {
    // CTR mode encryption and decryption are the same operation
    return encrypt_ctr(ciphertext, ctx, iv);
}

inline std::vector<uint8_t> AES::add_padding(const std::vector<uint8_t>& data) {
    size_t padding_length = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    std::vector<uint8_t> padded = data;
    
    for (size_t i = 0; i < padding_length; i++) {
        padded.push_back(static_cast<uint8_t>(padding_length));
    }
    
    return padded;
}

inline std::vector<uint8_t> AES::remove_padding(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        throw std::invalid_argument("Cannot remove padding from empty data");
    }
    
    uint8_t padding_length = data.back();
    if (padding_length == 0 || padding_length > BLOCK_SIZE || padding_length > data.size()) {
        throw std::invalid_argument("Invalid padding");
    }
    
    // Verify padding
    for (size_t i = data.size() - padding_length; i < data.size(); i++) {
        if (data[i] != padding_length) {
            throw std::invalid_argument("Invalid padding");
        }
    }
    
    return std::vector<uint8_t>(data.begin(), data.end() - padding_length);
}

inline void AES::xor_arrays(uint8_t* dest, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] ^= src[i];
    }
}

inline void AES::increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

} // namespace lockey
