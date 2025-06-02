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

} // namespace lockey
