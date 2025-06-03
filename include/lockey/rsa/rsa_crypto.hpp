#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include "../utils/common.hpp"

namespace lockey {
namespace rsa {

/**
 * @brief RSA key pair structure
 */
struct KeyPair {
    std::vector<uint8_t> n;     ///< Modulus
    std::vector<uint8_t> e;     ///< Public exponent
    std::vector<uint8_t> d;     ///< Private exponent
    std::vector<uint8_t> p;     ///< Prime factor 1
    std::vector<uint8_t> q;     ///< Prime factor 2
    std::vector<uint8_t> dp;    ///< d mod (p-1)
    std::vector<uint8_t> dq;    ///< d mod (q-1)
    std::vector<uint8_t> qi;    ///< q^(-1) mod p
    size_t key_size;            ///< Key size in bits
};

/**
 * @brief RSA public key structure
 */
struct PublicKey {
    std::vector<uint8_t> n;     ///< Modulus
    std::vector<uint8_t> e;     ///< Public exponent
    size_t key_size;            ///< Key size in bits
};

/**
 * @brief RSA private key structure
 */
struct PrivateKey {
    std::vector<uint8_t> n;     ///< Modulus
    std::vector<uint8_t> d;     ///< Private exponent
    std::vector<uint8_t> p;     ///< Prime factor 1 (optional)
    std::vector<uint8_t> q;     ///< Prime factor 2 (optional)
    std::vector<uint8_t> dp;    ///< d mod (p-1) (optional)
    std::vector<uint8_t> dq;    ///< d mod (q-1) (optional)
    std::vector<uint8_t> qi;    ///< q^(-1) mod p (optional)
    size_t key_size;            ///< Key size in bits
};

/**
 * @brief RSA padding schemes
 */
enum class PaddingScheme {
    PKCS1_V15,      ///< PKCS#1 v1.5 padding
    OAEP_SHA1,      ///< OAEP with SHA-1
    OAEP_SHA256,    ///< OAEP with SHA-256
    PSS_SHA256      ///< PSS with SHA-256
};

/**
 * @brief Big integer operations for RSA
 */
class BigInteger {
private:
    std::vector<uint32_t> digits_;
    bool negative_;

public:
    BigInteger();
    explicit BigInteger(uint64_t value);
    explicit BigInteger(const std::vector<uint8_t>& bytes);
    
    // Arithmetic operations
    BigInteger operator+(const BigInteger& other) const;
    BigInteger operator-(const BigInteger& other) const;
    BigInteger operator*(const BigInteger& other) const;
    BigInteger operator/(const BigInteger& other) const;
    BigInteger operator%(const BigInteger& other) const;
    
    // Comparison operations
    bool operator==(const BigInteger& other) const;
    bool operator!=(const BigInteger& other) const;
    bool operator<(const BigInteger& other) const;
    bool operator<=(const BigInteger& other) const;
    bool operator>(const BigInteger& other) const;
    bool operator>=(const BigInteger& other) const;
    
    // Modular operations
    BigInteger mod_pow(const BigInteger& exponent, const BigInteger& modulus) const;
    BigInteger mod_inverse(const BigInteger& modulus) const;
    BigInteger gcd(const BigInteger& other) const;
    
    // Utility methods
    bool is_zero() const;
    bool is_odd() const;
    size_t bit_length() const;
    std::vector<uint8_t> to_bytes() const;
    std::string to_string() const;
    
    // Prime operations
    static BigInteger generate_prime(size_t bit_length);
    bool is_prime() const;
    
private:
    void normalize();
    int compare_abs(const BigInteger& other) const;
};

/**
 * @brief RSA cryptographic operations
 */
class RSAImpl {
private:
    size_t key_size_;

    // PKCS#1 padding operations
    std::vector<uint8_t> pkcs1_pad_encryption(const std::vector<uint8_t>& data, 
                                             size_t key_size) const;
    std::vector<uint8_t> pkcs1_unpad_encryption(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> pkcs1_pad_signature(const std::vector<uint8_t>& hash,
                                            const std::string& hash_algorithm,
                                            size_t key_size) const;
    std::vector<uint8_t> pkcs1_unpad_signature(const std::vector<uint8_t>& data) const;
    
    // OAEP padding operations
    std::vector<uint8_t> oaep_pad(const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& label,
                                 const std::string& hash_algorithm,
                                 size_t key_size) const;
    std::vector<uint8_t> oaep_unpad(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& label,
                                   const std::string& hash_algorithm) const;
    
    // PSS padding operations
    std::vector<uint8_t> pss_pad(const std::vector<uint8_t>& hash,
                                const std::string& hash_algorithm,
                                size_t salt_length,
                                size_t key_size) const;
    bool pss_verify(const std::vector<uint8_t>& hash,
                   const std::vector<uint8_t>& signature,
                   const std::string& hash_algorithm,
                   size_t salt_length,
                   size_t key_size) const;

    // Core RSA operations
    std::vector<uint8_t> rsa_public_operation(const std::vector<uint8_t>& data,
                                             const PublicKey& key) const;
    std::vector<uint8_t> rsa_private_operation(const std::vector<uint8_t>& data,
                                              const PrivateKey& key) const;
    std::vector<uint8_t> rsa_private_operation_crt(const std::vector<uint8_t>& data,
                                                   const PrivateKey& key) const;

public:
    explicit RSAImpl(size_t key_size) : key_size_(key_size) {}

    // Key generation
    KeyPair generate_keypair() const;
    PublicKey extract_public_key(const KeyPair& keypair) const;
    PrivateKey extract_private_key(const KeyPair& keypair) const;

    // Encryption/Decryption
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const PublicKey& key,
                                PaddingScheme padding = PaddingScheme::OAEP_SHA256) const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const PrivateKey& key,
                                PaddingScheme padding = PaddingScheme::OAEP_SHA256) const;

    // Signing/Verification
    std::vector<uint8_t> sign(const std::vector<uint8_t>& hash,
                             const PrivateKey& key,
                             PaddingScheme padding = PaddingScheme::PSS_SHA256) const;
    bool verify(const std::vector<uint8_t>& hash,
               const std::vector<uint8_t>& signature,
               const PublicKey& key,
               PaddingScheme padding = PaddingScheme::PSS_SHA256) const;

    // Key validation
    bool validate_public_key(const PublicKey& key) const;
    bool validate_private_key(const PrivateKey& key) const;
    bool validate_keypair(const KeyPair& keypair) const;
};

/**
 * @brief RSA engine for managing different key sizes
 */
class RSAEngine {
public:
    enum class KeySize {
        RSA_2048 = 2048,
        RSA_3072 = 3072,
        RSA_4096 = 4096
    };

private:
    KeySize current_key_size_;
    std::unique_ptr<RSAImpl> rsa_impl_;

public:
    explicit RSAEngine(KeySize key_size = KeySize::RSA_2048) {
        set_key_size(key_size);
    }

    void set_key_size(KeySize key_size) {
        current_key_size_ = key_size;
        rsa_impl_ = std::make_unique<RSAImpl>(static_cast<size_t>(key_size));
    }

    KeySize get_key_size() const { return current_key_size_; }

    // Key operations
    KeyPair generate_keypair() {
        return rsa_impl_->generate_keypair();
    }

    PublicKey extract_public_key(const KeyPair& keypair) {
        return rsa_impl_->extract_public_key(keypair);
    }

    PrivateKey extract_private_key(const KeyPair& keypair) {
        return rsa_impl_->extract_private_key(keypair);
    }

    // Encryption/Decryption
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const PublicKey& key,
                                PaddingScheme padding = PaddingScheme::OAEP_SHA256) {
        return rsa_impl_->encrypt(plaintext, key, padding);
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const PrivateKey& key,
                                PaddingScheme padding = PaddingScheme::OAEP_SHA256) {
        return rsa_impl_->decrypt(ciphertext, key, padding);
    }

    // Signing/Verification
    std::vector<uint8_t> sign(const std::vector<uint8_t>& hash,
                             const PrivateKey& key,
                             PaddingScheme padding = PaddingScheme::PSS_SHA256) {
        return rsa_impl_->sign(hash, key, padding);
    }

    bool verify(const std::vector<uint8_t>& hash,
               const std::vector<uint8_t>& signature,
               const PublicKey& key,
               PaddingScheme padding = PaddingScheme::PSS_SHA256) {
        return rsa_impl_->verify(hash, signature, key, padding);
    }

    // Key validation
    bool validate_public_key(const PublicKey& key) {
        return rsa_impl_->validate_public_key(key);
    }

    bool validate_private_key(const PrivateKey& key) {
        return rsa_impl_->validate_private_key(key);
    }

    bool validate_keypair(const KeyPair& keypair) {
        return rsa_impl_->validate_keypair(keypair);
    }

    // Key encoding/decoding
    std::vector<uint8_t> encode_public_key_der(const PublicKey& key);
    std::vector<uint8_t> encode_private_key_der(const PrivateKey& key);
    std::string encode_public_key_pem(const PublicKey& key);
    std::string encode_private_key_pem(const PrivateKey& key);
    
    PublicKey decode_public_key_der(const std::vector<uint8_t>& der);
    PrivateKey decode_private_key_der(const std::vector<uint8_t>& der);
    PublicKey decode_public_key_pem(const std::string& pem);
    PrivateKey decode_private_key_pem(const std::string& pem);
};

} // namespace rsa
} // namespace lockey
