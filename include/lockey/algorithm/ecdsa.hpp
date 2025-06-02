#pragma once
#include "elliptic_curve.hpp"
#include "hash/sha256.hpp"
#include <vector>
#include <memory>
#include <random>
#include <stdexcept>

namespace lockey {

/**
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm) implementation
 * 
 * Provides digital signature functionality using elliptic curves.
 */
class ECDSA {
public:
    /**
     * @brief ECDSA Key Pair
     */
    struct KeyPair {
        Cypher private_key;         // Private key (scalar)
        ECPoint public_key;         // Public key (point)
        std::shared_ptr<ECCurve> curve; // Associated curve
        
        KeyPair(const Cypher& priv, const ECPoint& pub, std::shared_ptr<ECCurve> c)
            : private_key(priv), public_key(pub), curve(c) {}
    };
    
    /**
     * @brief ECDSA Signature
     */
    struct Signature {
        Cypher r;
        Cypher s;
        
        Signature(const Cypher& r_val, const Cypher& s_val) : r(r_val), s(s_val) {}
        
        // Encode signature in DER format
        std::vector<uint8_t> encode_der() const;
        
        // Encode signature in raw format (r || s)
        std::vector<uint8_t> encode_raw(size_t field_size) const;
        
        // Decode signature from DER format
        static Signature decode_der(const std::vector<uint8_t>& data);
        
        // Decode signature from raw format
        static Signature decode_raw(const std::vector<uint8_t>& data, size_t field_size);
    };
    
    /**
     * @brief Generate ECDSA key pair
     * 
     * @param curve The elliptic curve to use
     * @return Generated key pair
     */
    static KeyPair generate_key_pair(std::shared_ptr<ECCurve> curve);
    
    /**
     * @brief Sign a message hash using ECDSA
     * 
     * @param hash The hash of the message to sign
     * @param private_key The private key for signing
     * @param curve The elliptic curve
     * @return ECDSA signature
     */
    static Signature sign(const std::vector<uint8_t>& hash, 
                         const Cypher& private_key,
                         std::shared_ptr<ECCurve> curve);
    
    /**
     * @brief Verify an ECDSA signature
     * 
     * @param hash The hash of the original message
     * @param signature The signature to verify
     * @param public_key The public key for verification
     * @param curve The elliptic curve
     * @return true if signature is valid, false otherwise
     */
    static bool verify(const std::vector<uint8_t>& hash,
                      const Signature& signature,
                      const ECPoint& public_key,
                      std::shared_ptr<ECCurve> curve);
    
    /**
     * @brief Sign a message (with automatic hashing)
     * 
     * @param message The message to sign
     * @param private_key The private key for signing
     * @param curve The elliptic curve
     * @return ECDSA signature
     */
    static Signature sign_message(const std::vector<uint8_t>& message,
                                 const Cypher& private_key,
                                 std::shared_ptr<ECCurve> curve);
    
    /**
     * @brief Verify a message signature (with automatic hashing)
     * 
     * @param message The original message
     * @param signature The signature to verify
     * @param public_key The public key for verification
     * @param curve The elliptic curve
     * @return true if signature is valid, false otherwise
     */
    static bool verify_message(const std::vector<uint8_t>& message,
                              const Signature& signature,
                              const ECPoint& public_key,
                              std::shared_ptr<ECCurve> curve);

private:
    /**
     * @brief Generate a cryptographically secure random number in range [1, n-1]
     * 
     * @param n The upper bound (exclusive)
     * @return Random number in the specified range
     */
    static Cypher generate_random_scalar(const Cypher& n);
    
    /**
     * @brief Modular inverse using extended Euclidean algorithm
     * 
     * @param a The number to find inverse of
     * @param m The modulus
     * @return Modular inverse of a mod m
     */
    static Cypher mod_inverse(const Cypher& a, const Cypher& m);
};

} // namespace lockey
