#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include "../utils/common.hpp"

namespace lockey {
namespace crypto {

/**
 * @brief Base class for symmetric ciphers
 */
class CipherBase {
public:
    virtual ~CipherBase() = default;
    
    virtual void set_key(const std::vector<uint8_t>& key) = 0;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& iv = {},
                                        const std::vector<uint8_t>& aad = {}) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& iv = {},
                                        const std::vector<uint8_t>& aad = {}) = 0;
    
    virtual size_t key_size() const = 0;
    virtual size_t block_size() const = 0;
    virtual size_t iv_size() const = 0;
    virtual bool is_aead() const = 0;
};

/**
 * @brief AES implementation
 */
class AES {
private:
    static constexpr size_t BLOCK_SIZE = 16;
    
    std::vector<uint8_t> key_;
    std::vector<uint32_t> round_keys_;
    size_t nr_; // Number of rounds
    
    // AES S-box
    static const std::array<uint8_t, 256> SBOX;
    static const std::array<uint8_t, 256> INV_SBOX;
    
    // AES round constants
    static const std::array<uint8_t, 11> RCON;
    
    // AES operations
    void key_expansion();
    void add_round_key(std::array<uint8_t, 16>& state, size_t round) const;
    void sub_bytes(std::array<uint8_t, 16>& state) const;
    void inv_sub_bytes(std::array<uint8_t, 16>& state) const;
    void shift_rows(std::array<uint8_t, 16>& state) const;
    void inv_shift_rows(std::array<uint8_t, 16>& state) const;
    void mix_columns(std::array<uint8_t, 16>& state) const;
    void inv_mix_columns(std::array<uint8_t, 16>& state) const;
    
    uint8_t gf_mul(uint8_t a, uint8_t b) const;

public:
    explicit AES(const std::vector<uint8_t>& key);
    
    void set_key(const std::vector<uint8_t>& key);
    std::array<uint8_t, 16> encrypt_block(const std::array<uint8_t, 16>& plaintext) const;
    std::array<uint8_t, 16> decrypt_block(const std::array<uint8_t, 16>& ciphertext) const;
    
    size_t key_size() const { return key_.size(); }
    static constexpr size_t block_size() { return BLOCK_SIZE; }
};

/**
 * @brief AES-GCM implementation
 */
class AES_GCM : public CipherBase {
private:
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    
    AES aes_;
    
    // GCM operations
    std::array<uint8_t, 16> ghash(const std::vector<uint8_t>& data,
                                 const std::array<uint8_t, 16>& h) const;
    std::array<uint8_t, 16> gcm_auth(const std::vector<uint8_t>& ciphertext,
                                    const std::vector<uint8_t>& aad,
                                    const std::array<uint8_t, 16>& h,
                                    const std::array<uint8_t, 16>& j0) const;
    std::array<uint8_t, 16> gcm_ctr_inc(const std::array<uint8_t, 16>& block) const;
    
    void gf_mul_128(std::array<uint8_t, 16>& x, const std::array<uint8_t, 16>& y) const;

public:
    explicit AES_GCM(const std::vector<uint8_t>& key) : aes_(key) {}
    
    void set_key(const std::vector<uint8_t>& key) override {
        aes_.set_key(key);
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& iv = {},
                                const std::vector<uint8_t>& aad = {}) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const std::vector<uint8_t>& iv = {},
                                const std::vector<uint8_t>& aad = {}) override;
    
    size_t key_size() const override { return aes_.key_size(); }
    size_t block_size() const override { return BLOCK_SIZE; }
    size_t iv_size() const override { return IV_SIZE; }
    bool is_aead() const override { return true; }
    
    static constexpr size_t tag_size() { return TAG_SIZE; }
};

/**
 * @brief ChaCha20 stream cipher implementation
 */
class ChaCha20 {
private:
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    
    std::array<uint32_t, 16> state_;
    
    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) const;
    void chacha20_block(std::array<uint32_t, 16>& working_state) const;
    uint32_t rotl(uint32_t value, int shift) const;

public:
    ChaCha20() = default;
    ChaCha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, uint32_t counter = 0) {
        set_key(key, nonce, counter);
    }
    
    void set_key(const std::vector<uint8_t>& key, 
                 const std::vector<uint8_t>& nonce,
                 uint32_t counter = 0);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data);
    
    static constexpr size_t key_size() { return KEY_SIZE; }
    static constexpr size_t nonce_size() { return NONCE_SIZE; }
    static constexpr size_t block_size() { return BLOCK_SIZE; }
};

/**
 * @brief Poly1305 MAC implementation
 */
class Poly1305 {
private:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t TAG_SIZE = 16;
    
    std::array<uint8_t, 32> key_;
    uint32_t r_[5];
    uint32_t s_[4];
    uint32_t h_[5];
    
    void clamp_r();
    void poly1305_block(const uint8_t* block, size_t len);

public:
    void set_key(const std::vector<uint8_t>& key);
    std::array<uint8_t, 16> compute(const std::vector<uint8_t>& data);
    
    static constexpr size_t key_size() { return KEY_SIZE; }
    static constexpr size_t tag_size() { return TAG_SIZE; }
};

/**
 * @brief ChaCha20-Poly1305 AEAD implementation
 */
class ChaCha20_Poly1305 : public CipherBase {
private:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    
    ChaCha20 chacha20_;
    Poly1305 poly1305_;
    
    std::vector<uint8_t> poly1305_key_gen(const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& nonce);

public:
    explicit ChaCha20_Poly1305(const std::vector<uint8_t>& key) {
        set_key(key);
    }
    
    void set_key(const std::vector<uint8_t>& key) override;
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& iv = {},
                                const std::vector<uint8_t>& aad = {}) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const std::vector<uint8_t>& iv = {},
                                const std::vector<uint8_t>& aad = {}) override;
    
    size_t key_size() const override { return KEY_SIZE; }
    size_t block_size() const override { return 1; } // Stream cipher
    size_t iv_size() const override { return NONCE_SIZE; }
    bool is_aead() const override { return true; }
    
    static constexpr size_t tag_size() { return TAG_SIZE; }
};

} // namespace crypto
} // namespace lockey
