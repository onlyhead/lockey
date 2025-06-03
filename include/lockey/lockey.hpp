#pragma once

#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <random>

#include "crypto/algorithms.hpp"
#include "crypto/engines.hpp"
#include "hash/hash_functions.hpp"
#include "hash/engines.hpp"
#include "ec/elliptic_curve.hpp"
#include "ec/engines.hpp"
#include "rsa/rsa_crypto.hpp"
#include "utils/key_io.hpp"
#include "utils/common.hpp"

// Include implementation files
#include "crypto/crypto_impl.hpp"
#include "hash/hash_impl.hpp"
#include "ec/ec_impl.hpp"
#include "rsa/rsa_impl_simple.hpp"

namespace lockey {

/**
 * @brief Main Lockey cryptographic library class
 * 
 * This class provides a unified interface for various cryptographic operations
 * including encryption/decryption, digital signatures, and key management.
 */
class Lockey {
public:
    /**
     * @brief Supported cryptographic algorithms
     */
    enum class Algorithm {
        AES_256_GCM,    ///< AES-256 in GCM mode
        AES_128_GCM,    ///< AES-128 in GCM mode
        ChaCha20_Poly1305, ///< ChaCha20-Poly1305 AEAD
        RSA_2048,       ///< RSA with 2048-bit keys
        RSA_4096,       ///< RSA with 4096-bit keys
        ECDSA_P256,     ///< ECDSA with P-256 curve
        ECDSA_P384,     ///< ECDSA with P-384 curve
        ECDSA_P521,     ///< ECDSA with P-521 curve
        Ed25519         ///< EdDSA with Curve25519
    };

    /**
     * @brief Hash algorithm types
     */
    enum class HashAlgorithm {
        SHA256,         ///< SHA-256
        SHA384,         ///< SHA-384
        SHA512,         ///< SHA-512
        BLAKE2b         ///< BLAKE2b
    };

    /**
     * @brief Key types for asymmetric cryptography
     */
    enum class KeyType {
        PUBLIC,         ///< Public key
        PRIVATE         ///< Private key
    };

    /**
     * @brief Result structure for cryptographic operations
     */
    struct CryptoResult {
        bool success;                ///< Operation success status
        std::vector<uint8_t> data;   ///< Result data
        std::string error_message;   ///< Error message if unsuccessful
    };

    /**
     * @brief Key pair structure
     */
    struct KeyPair {
        std::vector<uint8_t> public_key;    ///< Public key data
        std::vector<uint8_t> private_key;   ///< Private key data
        Algorithm algorithm;                 ///< Associated algorithm
    };

private:
    Algorithm current_algorithm_;
    HashAlgorithm current_hash_;
    std::unique_ptr<crypto::CryptoEngine> crypto_engine_;
    std::unique_ptr<hash::HashEngine> hash_engine_;
    std::unique_ptr<ec::ECEngine> ec_engine_;
    std::unique_ptr<rsa::RSAEngine> rsa_engine_;

public:
    /**
     * @brief Constructor
     * @param algorithm Default algorithm to use
     * @param hash_algo Default hash algorithm to use
     */
    explicit Lockey(Algorithm algorithm = Algorithm::AES_256_GCM, 
                    HashAlgorithm hash_algo = HashAlgorithm::SHA256);

    /**
     * @brief Destructor
     */
    ~Lockey() = default;

    // Copy and move constructors/operators
    Lockey(const Lockey&) = delete;
    Lockey& operator=(const Lockey&) = delete;
    Lockey(Lockey&&) = default;
    Lockey& operator=(Lockey&&) = default;

    // Configuration methods
    /**
     * @brief Set the current cryptographic algorithm
     * @param algorithm Algorithm to use
     */
    void set_algorithm(Algorithm algorithm);

    /**
     * @brief Set the current hash algorithm
     * @param hash_algo Hash algorithm to use
     */
    void set_hash_algorithm(HashAlgorithm hash_algo);

    /**
     * @brief Get the current algorithm
     * @return Current algorithm
     */
    Algorithm get_algorithm() const { return current_algorithm_; }

    /**
     * @brief Get the current hash algorithm
     * @return Current hash algorithm
     */
    HashAlgorithm get_hash_algorithm() const { return current_hash_; }

    // Symmetric encryption/decryption
    /**
     * @brief Encrypt data using symmetric encryption
     * @param plaintext Data to encrypt
     * @param key Encryption key
     * @param associated_data Optional associated data for AEAD modes
     * @return Encryption result
     */
    CryptoResult encrypt(const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& associated_data = {});

    /**
     * @brief Decrypt data using symmetric encryption
     * @param ciphertext Data to decrypt
     * @param key Decryption key
     * @param associated_data Optional associated data for AEAD modes
     * @return Decryption result
     */
    CryptoResult decrypt(const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& associated_data = {});

    // Asymmetric encryption/decryption
    /**
     * @brief Encrypt data using asymmetric encryption (RSA)
     * @param plaintext Data to encrypt
     * @param public_key Public key for encryption
     * @return Encryption result
     */
    CryptoResult encrypt_asymmetric(const std::vector<uint8_t>& plaintext,
                                   const std::vector<uint8_t>& public_key);

    /**
     * @brief Decrypt data using asymmetric encryption (RSA)
     * @param ciphertext Data to decrypt
     * @param private_key Private key for decryption
     * @return Decryption result
     */
    CryptoResult decrypt_asymmetric(const std::vector<uint8_t>& ciphertext,
                                   const std::vector<uint8_t>& private_key);

    // Digital signatures
    /**
     * @brief Sign data with a private key
     * @param data Data to sign
     * @param private_key Private key for signing
     * @return Signature result
     */
    CryptoResult sign(const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& private_key);

    /**
     * @brief Verify a signature
     * @param data Original data
     * @param signature Signature to verify
     * @param public_key Public key for verification
     * @return Verification result
     */
    CryptoResult verify(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key);

    // Key generation
    /**
     * @brief Generate a key pair for asymmetric cryptography
     * @return Generated key pair
     */
    KeyPair generate_keypair();

    /**
     * @brief Generate a symmetric key
     * @param key_size Key size in bytes
     * @return Generated key
     */
    CryptoResult generate_symmetric_key(size_t key_size = 32);

    // Hashing
    /**
     * @brief Compute hash of data
     * @param data Data to hash
     * @return Hash result
     */
    CryptoResult hash(const std::vector<uint8_t>& data);

    /**
     * @brief Compute HMAC of data
     * @param data Data to authenticate
     * @param key HMAC key
     * @return HMAC result
     */
    CryptoResult hmac(const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& key);

    // Key I/O operations
    /**
     * @brief Save a key to file
     * @param key Key data
     * @param filename Output filename
     * @param key_type Type of key (public/private)
     * @param format Output format (PEM/DER)
     * @return Success status
     */
    bool save_key_to_file(const std::vector<uint8_t>& key,
                         const std::string& filename,
                         KeyType key_type,
                         utils::KeyFormat format = utils::KeyFormat::PEM);

    /**
     * @brief Load a key from file
     * @param filename Input filename
     * @param key_type Expected key type
     * @return Loaded key data
     */
    CryptoResult load_key_from_file(const std::string& filename,
                                   KeyType key_type);

    /**
     * @brief Save a key pair to files
     * @param keypair Key pair to save
     * @param public_filename Public key filename
     * @param private_filename Private key filename
     * @param format Output format
     * @return Success status
     */
    bool save_keypair_to_files(const KeyPair& keypair,
                              const std::string& public_filename,
                              const std::string& private_filename,
                              utils::KeyFormat format = utils::KeyFormat::PEM);

    /**
     * @brief Load a key pair from files
     * @param public_filename Public key filename
     * @param private_filename Private key filename
     * @return Loaded key pair
     */
    CryptoResult load_keypair_from_files(const std::string& public_filename,
                                        const std::string& private_filename);

    // Utility methods
    /**
     * @brief Convert data to hexadecimal string
     * @param data Data to convert
     * @return Hexadecimal string
     */
    static std::string to_hex(const std::vector<uint8_t>& data);

    /**
     * @brief Convert hexadecimal string to data
     * @param hex Hexadecimal string
     * @return Converted data
     */
    static std::vector<uint8_t> from_hex(const std::string& hex);

    /**
     * @brief Get algorithm name as string
     * @param algorithm Algorithm to convert
     * @return Algorithm name
     */
    static std::string algorithm_to_string(Algorithm algorithm);

    /**
     * @brief Get hash algorithm name as string
     * @param hash_algo Hash algorithm to convert
     * @return Hash algorithm name
     */
    static std::string hash_algorithm_to_string(HashAlgorithm hash_algo);

private:
    void initialize_engines();
    bool is_symmetric_algorithm(Algorithm algo) const;
    bool is_asymmetric_algorithm(Algorithm algo) const;
    bool is_signature_algorithm(Algorithm algo) const;
};

} // namespace lockey

// Inline implementations
namespace lockey {

inline Lockey::Lockey(Algorithm algorithm, HashAlgorithm hash_algo) 
    : current_algorithm_(algorithm), current_hash_(hash_algo) {
    initialize_engines();
}

inline void Lockey::set_algorithm(Algorithm algorithm) {
    current_algorithm_ = algorithm;
    initialize_engines();
}

inline void Lockey::set_hash_algorithm(HashAlgorithm hash_algo) {
    current_hash_ = hash_algo;
    initialize_engines();
}

inline void Lockey::initialize_engines() {
    // Initialize hash engine
    switch (current_hash_) {
        case HashAlgorithm::SHA256:
            hash_engine_ = std::make_unique<hash::SHA256Engine>();
            break;
        case HashAlgorithm::SHA384:
            hash_engine_ = std::make_unique<hash::SHA384Engine>();
            break;
        case HashAlgorithm::SHA512:
            hash_engine_ = std::make_unique<hash::SHA512Engine>();
            break;
        case HashAlgorithm::BLAKE2b:
            // BLAKE2b would need separate implementation
            throw std::runtime_error("BLAKE2b not implemented yet");
    }
    
    // Initialize crypto engines based on current algorithm
    switch (current_algorithm_) {
        case Algorithm::AES_256_GCM:
        case Algorithm::AES_128_GCM:
            crypto_engine_ = std::make_unique<crypto::AESGCMEngine>();
            break;
        case Algorithm::ChaCha20_Poly1305:
            crypto_engine_ = std::make_unique<crypto::ChaCha20Engine>();
            break;
        case Algorithm::RSA_2048:
        case Algorithm::RSA_4096:
            rsa_engine_ = std::make_unique<rsa::RSAEngine>();
            break;
        case Algorithm::ECDSA_P256:
        case Algorithm::ECDSA_P384:
        case Algorithm::ECDSA_P521:
            ec_engine_ = std::make_unique<ec::P256Engine>();
            break;
        case Algorithm::Ed25519:
            throw std::runtime_error("Ed25519 not implemented yet");
    }
}

inline Lockey::CryptoResult Lockey::encrypt(const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& associated_data) {
    try {
        if (!is_symmetric_algorithm(current_algorithm_)) {
            return {false, {}, "Current algorithm is not suitable for symmetric encryption"};
        }
        
        std::vector<uint8_t> result;
        
        switch (current_algorithm_) {
            case Algorithm::AES_256_GCM:
            case Algorithm::AES_128_GCM: {
                crypto::AES_GCM aes_gcm(key);
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint8_t> dis(0, 255);
                
                std::vector<uint8_t> iv(12);
                for (auto& byte : iv) byte = dis(gen);
                
                auto ciphertext = aes_gcm.encrypt(plaintext, iv, associated_data);
                
                // Prepend IV to result
                result.insert(result.end(), iv.begin(), iv.end());
                result.insert(result.end(), ciphertext.begin(), ciphertext.end());
                break;
            }
            case Algorithm::ChaCha20_Poly1305: {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint8_t> dis(0, 255);
                
                std::vector<uint8_t> nonce(12);
                for (auto& byte : nonce) byte = dis(gen);
                
                crypto::ChaCha20 chacha(key, nonce);
                auto ciphertext = chacha.encrypt(plaintext);
                
                // Prepend nonce to result
                result.insert(result.end(), nonce.begin(), nonce.end());
                result.insert(result.end(), ciphertext.begin(), ciphertext.end());
                break;
            }
            default:
                return {false, {}, "Unsupported algorithm for symmetric encryption"};
        }
        
        return {true, result, ""};
    } catch (const std::exception& e) {
        return {false, {}, e.what()};
    }
}

inline Lockey::CryptoResult Lockey::decrypt(const std::vector<uint8_t>& ciphertext,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& associated_data) {
    try {
        if (!is_symmetric_algorithm(current_algorithm_)) {
            return {false, {}, "Current algorithm is not suitable for symmetric decryption"};
        }
        
        switch (current_algorithm_) {
            case Algorithm::AES_256_GCM:
            case Algorithm::AES_128_GCM: {
                if (ciphertext.size() < 12) {
                    return {false, {}, "Ciphertext too short for AES-GCM (missing IV)"};
                }
                
                std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + 12);
                std::vector<uint8_t> ct(ciphertext.begin() + 12, ciphertext.end());
                
                crypto::AES_GCM aes_gcm(key);
                auto plaintext = aes_gcm.decrypt(ct, iv, associated_data);
                
                return {true, plaintext, ""};
            }
            case Algorithm::ChaCha20_Poly1305: {
                if (ciphertext.size() < 12) {
                    return {false, {}, "Ciphertext too short for ChaCha20 (missing nonce)"};
                }
                
                std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 12);
                std::vector<uint8_t> ct(ciphertext.begin() + 12, ciphertext.end());
                
                crypto::ChaCha20 chacha(key, nonce);
                auto plaintext = chacha.decrypt(ct);
                
                return {true, plaintext, ""};
            }
            default:
                return {false, {}, "Unsupported algorithm for symmetric decryption"};
        }
    } catch (const std::exception& e) {
        return {false, {}, e.what()};
    }
}

inline Lockey::KeyPair Lockey::generate_keypair() {
    try {
        switch (current_algorithm_) {
            case Algorithm::RSA_2048: {
                rsa::RSAImpl rsa_impl(2048);
                auto keypair = rsa_impl.generate_keypair();
                
                // Serialize keys (simplified format)
                KeyPair result;
                result.algorithm = current_algorithm_;
                result.public_key = keypair.n;
                result.private_key = keypair.d;
                return result;
            }
            case Algorithm::RSA_4096: {
                rsa::RSAImpl rsa_impl(4096);
                auto keypair = rsa_impl.generate_keypair();
                
                KeyPair result;
                result.algorithm = current_algorithm_;
                result.public_key = keypair.n;
                result.private_key = keypair.d;
                return result;
            }
            case Algorithm::ECDSA_P256: {
                ec::P256Curve curve;
                auto keypair = curve.generate_keypair();
                
                KeyPair result;
                result.algorithm = current_algorithm_;
                result.private_key = keypair.private_key;
                
                // Serialize public key
                result.public_key.push_back(0x04); // Uncompressed point
                result.public_key.insert(result.public_key.end(), 
                                       keypair.public_key.x.begin(), 
                                       keypair.public_key.x.end());
                result.public_key.insert(result.public_key.end(), 
                                       keypair.public_key.y.begin(), 
                                       keypair.public_key.y.end());
                return result;
            }
            default:
                throw std::runtime_error("Key generation not supported for current algorithm");
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Key generation failed: " + std::string(e.what()));
    }
}

inline Lockey::CryptoResult Lockey::sign(const std::vector<uint8_t>& data,
                                        const std::vector<uint8_t>& private_key) {
    try {
        if (!is_signature_algorithm(current_algorithm_)) {
            return {false, {}, "Current algorithm does not support signing"};
        }
        
        // Hash the data first
        auto hash_result = hash(data);
        if (!hash_result.success) {
            return {false, {}, "Failed to hash data: " + hash_result.error_message};
        }
        
        switch (current_algorithm_) {
            case Algorithm::ECDSA_P256: {
                ec::P256Curve curve;
                auto signature = curve.sign(hash_result.data, private_key);
                
                // Serialize signature (r || s)
                std::vector<uint8_t> result;
                result.insert(result.end(), signature.r.begin(), signature.r.end());
                result.insert(result.end(), signature.s.begin(), signature.s.end());
                
                return {true, result, ""};
            }
            case Algorithm::RSA_2048:
            case Algorithm::RSA_4096: {
                // For RSA, we need to reconstruct the full private key
                // This is simplified - in practice, you'd store the full key
                rsa::RSAImpl rsa_impl(current_algorithm_ == Algorithm::RSA_2048 ? 2048 : 4096);
                
                // This is a placeholder - proper RSA signing would need the full private key structure
                return {false, {}, "RSA signing requires full private key structure"};
            }
            default:
                return {false, {}, "Signing not implemented for current algorithm"};
        }
    } catch (const std::exception& e) {
        return {false, {}, e.what()};
    }
}

inline Lockey::CryptoResult Lockey::verify(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& signature,
                                          const std::vector<uint8_t>& public_key) {
    try {
        if (!is_signature_algorithm(current_algorithm_)) {
            return {false, {}, "Current algorithm does not support verification"};
        }
        
        // Hash the data first
        auto hash_result = hash(data);
        if (!hash_result.success) {
            return {false, {}, "Failed to hash data: " + hash_result.error_message};
        }
        
        switch (current_algorithm_) {
            case Algorithm::ECDSA_P256: {
                if (signature.size() != 64 || public_key.size() != 65 || public_key[0] != 0x04) {
                    return {false, {}, "Invalid signature or public key format"};
                }
                
                ec::P256Curve curve;
                ec::ECDSASignature sig;
                sig.r = std::vector<uint8_t>(signature.begin(), signature.begin() + 32);
                sig.s = std::vector<uint8_t>(signature.begin() + 32, signature.end());
                
                ec::ECPoint pubkey;
                pubkey.x = std::vector<uint8_t>(public_key.begin() + 1, public_key.begin() + 33);
                pubkey.y = std::vector<uint8_t>(public_key.begin() + 33, public_key.end());
                pubkey.is_infinity = false;
                
                bool valid = curve.verify(hash_result.data, sig, pubkey);
                return {valid, {}, valid ? "" : "Signature verification failed"};
            }
            default:
                return {false, {}, "Verification not implemented for current algorithm"};
        }
    } catch (const std::exception& e) {
        return {false, {}, e.what()};
    }
}

inline Lockey::CryptoResult Lockey::hash(const std::vector<uint8_t>& data) {
    try {
        switch (current_hash_) {
            case HashAlgorithm::SHA256: {
                hash::SHA256 sha256;
                auto result = sha256.compute(data);
                return {true, result, ""};
            }
            case HashAlgorithm::SHA384: {
                hash::SHA384 sha384;
                auto result = sha384.compute(data);
                return {true, result, ""};
            }
            case HashAlgorithm::SHA512: {
                hash::SHA512 sha512;
                auto result = sha512.compute(data);
                return {true, result, ""};
            }
            default:
                return {false, {}, "Unsupported hash algorithm"};
        }
    } catch (const std::exception& e) {
        return {false, {}, e.what()};
    }
}

inline bool Lockey::save_keypair_to_files(const KeyPair& keypair,
                                        const std::string& public_filename,
                                        const std::string& private_filename,
                                        utils::KeyFormat format) {
    try {
        switch (keypair.algorithm) {
            case Algorithm::ECDSA_P256:
                utils::KeyIO::save_ec_private_key(keypair.private_key, private_filename);
                
                // Deserialize public key
                if (keypair.public_key.size() == 65 && keypair.public_key[0] == 0x04) {
                    utils::KeyIO::save_ec_public_key(keypair.public_key, public_filename);
                }
                break;
                
            default:
                return false;
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

inline Lockey::CryptoResult Lockey::load_keypair_from_files(const std::string& public_filename,
                                                               const std::string& private_filename) {
    try {
        KeyPair keypair;
        keypair.algorithm = current_algorithm_;
        
        switch (current_algorithm_) {
            case Algorithm::ECDSA_P256: {
                keypair.private_key = utils::KeyIO::load_ec_private_key(private_filename);
                keypair.public_key = utils::KeyIO::load_ec_public_key(public_filename);
                break;
            }
            default:
                return {false, {}, "Key loading not supported for algorithm"};
        }
        
        // Serialize the keypair into the result
        CryptoResult result;
        result.success = true;
        // For simplicity, just return the private key data - in a real implementation
        // you might want to serialize both keys properly
        result.data = keypair.private_key;
        return result;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load keypair: " + std::string(e.what()));
    }
}

inline Lockey::CryptoResult Lockey::generate_symmetric_key(size_t key_size) {
    try {
        CryptoResult result;
        result.success = true;
        result.data = utils::Common::generate_random_bytes(key_size);
        return result;
    } catch (const std::exception& e) {
        CryptoResult result;
        result.success = false;
        result.error_message = "Failed to generate symmetric key: " + std::string(e.what());
        return result;
    }
}

inline std::string Lockey::to_hex(const std::vector<uint8_t>& data) {
    return utils::to_hex(data);
}

inline std::vector<uint8_t> Lockey::from_hex(const std::string& hex) {
    return utils::from_hex(hex);
}

inline std::string Lockey::algorithm_to_string(Algorithm algorithm) {
    switch (algorithm) {
        case Algorithm::AES_256_GCM: return "AES-256-GCM";
        case Algorithm::AES_128_GCM: return "AES-128-GCM";
        case Algorithm::ChaCha20_Poly1305: return "ChaCha20-Poly1305";
        case Algorithm::RSA_2048: return "RSA-2048";
        case Algorithm::RSA_4096: return "RSA-4096";
        case Algorithm::ECDSA_P256: return "ECDSA-P256";
        case Algorithm::ECDSA_P384: return "ECDSA-P384";
        case Algorithm::ECDSA_P521: return "ECDSA-P521";
        case Algorithm::Ed25519: return "Ed25519";
        default: return "Unknown";
    }
}

inline std::string Lockey::hash_algorithm_to_string(HashAlgorithm hash_algo) {
    switch (hash_algo) {
        case HashAlgorithm::SHA256: return "SHA-256";
        case HashAlgorithm::SHA384: return "SHA-384";
        case HashAlgorithm::SHA512: return "SHA-512";
        case HashAlgorithm::BLAKE2b: return "BLAKE2b";
        default: return "Unknown";
    }
}

inline bool Lockey::is_symmetric_algorithm(Algorithm algo) const {
    return algo == Algorithm::AES_256_GCM || 
           algo == Algorithm::AES_128_GCM || 
           algo == Algorithm::ChaCha20_Poly1305;
}

inline bool Lockey::is_asymmetric_algorithm(Algorithm algo) const {
    return algo == Algorithm::RSA_2048 || 
           algo == Algorithm::RSA_4096 ||
           algo == Algorithm::ECDSA_P256 || 
           algo == Algorithm::ECDSA_P384 || 
           algo == Algorithm::ECDSA_P521 ||
           algo == Algorithm::Ed25519;
}

inline bool Lockey::is_signature_algorithm(Algorithm algo) const {
    return algo == Algorithm::RSA_2048 || 
           algo == Algorithm::RSA_4096 ||
           algo == Algorithm::ECDSA_P256 || 
           algo == Algorithm::ECDSA_P384 || 
           algo == Algorithm::ECDSA_P521 ||
           algo == Algorithm::Ed25519;
}

} // namespace lockey
