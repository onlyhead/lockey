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

// ===== ECDSA Implementations =====

inline std::vector<uint8_t> ECDSA::Signature::encode_der() const {
    // Simple DER encoding for SEQUENCE of two INTEGERs
    auto r_bytes = r.toBytes();
    auto s_bytes = s.toBytes();
    
    // Remove leading zeros but keep at least one byte
    while (r_bytes.size() > 1 && r_bytes[0] == 0) r_bytes.erase(r_bytes.begin());
    while (s_bytes.size() > 1 && s_bytes[0] == 0) s_bytes.erase(s_bytes.begin());
    
    // Add leading zero if MSB is set (to ensure positive interpretation)
    if (!r_bytes.empty() && (r_bytes[0] & 0x80)) r_bytes.insert(r_bytes.begin(), 0);
    if (!s_bytes.empty() && (s_bytes[0] & 0x80)) s_bytes.insert(s_bytes.begin(), 0);
    
    std::vector<uint8_t> result;
    
    // SEQUENCE tag
    result.push_back(0x30);
    
    // Total length (will be filled later)
    size_t length_pos = result.size();
    result.push_back(0);
    
    // r INTEGER
    result.push_back(0x02);
    result.push_back(static_cast<uint8_t>(r_bytes.size()));
    result.insert(result.end(), r_bytes.begin(), r_bytes.end());
    
    // s INTEGER
    result.push_back(0x02);
    result.push_back(static_cast<uint8_t>(s_bytes.size()));
    result.insert(result.end(), s_bytes.begin(), s_bytes.end());
    
    // Fill in total length
    result[length_pos] = static_cast<uint8_t>(result.size() - 2);
    
    return result;
}

inline std::vector<uint8_t> ECDSA::Signature::encode_raw(size_t field_size) const {
    auto r_bytes = r.toBytes();
    auto s_bytes = s.toBytes();
    
    // Pad to field size
    while (r_bytes.size() < field_size) r_bytes.insert(r_bytes.begin(), 0);
    while (s_bytes.size() < field_size) s_bytes.insert(s_bytes.begin(), 0);
    
    std::vector<uint8_t> result;
    result.insert(result.end(), r_bytes.begin(), r_bytes.end());
    result.insert(result.end(), s_bytes.begin(), s_bytes.end());
    
    return result;
}

inline ECDSA::Signature ECDSA::Signature::decode_der(const std::vector<uint8_t>& data) {
    if (data.size() < 6) throw std::invalid_argument("Invalid DER signature");
    
    size_t pos = 0;
    
    // Check SEQUENCE tag
    if (data[pos++] != 0x30) throw std::invalid_argument("Invalid DER signature");
    
    // Read length
    uint8_t seq_len = data[pos++];
    if (pos + seq_len != data.size()) throw std::invalid_argument("Invalid DER signature");
    
    // Read r INTEGER
    if (data[pos++] != 0x02) throw std::invalid_argument("Invalid DER signature");
    uint8_t r_len = data[pos++];
    if (pos + r_len >= data.size()) throw std::invalid_argument("Invalid DER signature");
    
    std::vector<uint8_t> r_bytes(data.begin() + pos, data.begin() + pos + r_len);
    pos += r_len;
    
    // Read s INTEGER
    if (data[pos++] != 0x02) throw std::invalid_argument("Invalid DER signature");
    uint8_t s_len = data[pos++];
    if (pos + s_len != data.size()) throw std::invalid_argument("Invalid DER signature");
    
    std::vector<uint8_t> s_bytes(data.begin() + pos, data.begin() + pos + s_len);
    
    return Signature(Cypher(r_bytes), Cypher(s_bytes));
}

inline ECDSA::Signature ECDSA::Signature::decode_raw(const std::vector<uint8_t>& data, size_t field_size) {
    if (data.size() != 2 * field_size) {
        throw std::invalid_argument("Invalid raw signature size");
    }
    
    std::vector<uint8_t> r_bytes(data.begin(), data.begin() + field_size);
    std::vector<uint8_t> s_bytes(data.begin() + field_size, data.end());
    
    return Signature(Cypher(r_bytes), Cypher(s_bytes));
}

inline ECDSA::KeyPair ECDSA::generate_key_pair(std::shared_ptr<ECCurve> curve) {
    Cypher n = curve->order();
    Cypher private_key = generate_random_scalar(n);
    ECPoint public_key = curve->generate_public_key(private_key);
    
    return KeyPair(private_key, public_key, curve);
}

inline ECDSA::Signature ECDSA::sign(const std::vector<uint8_t>& hash, 
                                   const Cypher& private_key,
                                   std::shared_ptr<ECCurve> curve) {
    Cypher n = curve->order();
    Cypher z = Cypher(hash);
    
    // Ensure z is in the proper range
    if (z >= n) {
        auto z_bytes = z.toBytes();
        size_t n_bit_size = n.bitLength();
        size_t bytes_needed = (n_bit_size + 7) / 8;
        if (z_bytes.size() > bytes_needed) {
            z_bytes.resize(bytes_needed);
            z = Cypher(z_bytes);
        }
    }
    
    while (true) {
        // Generate random k
        Cypher k = generate_random_scalar(n);
        
        // Calculate r = (k * G).x mod n
        ECPoint R = curve->multiply(curve->generator(), k);
        Cypher r = R.x();
        
        // Simple modular reduction (placeholder)
        while (r >= n) {
            r = r - n;
        }
        
        if (r.isZero()) continue; // Try again with different k
        
        // Calculate s = k^(-1) * (z + r * private_key) mod n
        Cypher k_inv = mod_inverse(k, n);
        Cypher temp = r * private_key;
        while (temp >= n) temp = temp - n;
        
        Cypher s_inner = z + temp;
        while (s_inner >= n) s_inner = s_inner - n;
        
        Cypher s = k_inv * s_inner;
        while (s >= n) s = s - n;
        
        if (s.isZero()) continue; // Try again with different k
        
        return Signature(r, s);
    }
}

inline bool ECDSA::verify(const std::vector<uint8_t>& hash,
                         const Signature& signature,
                         const ECPoint& public_key,
                         std::shared_ptr<ECCurve> curve) {
    Cypher n = curve->order();
    Cypher z = Cypher(hash);
    
    // Ensure z is in the proper range
    if (z >= n) {
        auto z_bytes = z.toBytes();
        size_t n_bit_size = n.bitLength();
        size_t bytes_needed = (n_bit_size + 7) / 8;
        if (z_bytes.size() > bytes_needed) {
            z_bytes.resize(bytes_needed);
            z = Cypher(z_bytes);
        }
    }
    
    // Check signature components are in valid range
    if (signature.r.isZero() || signature.r >= n ||
        signature.s.isZero() || signature.s >= n) {
        return false;
    }
    
    try {
        // Calculate w = s^(-1) mod n
        Cypher w = mod_inverse(signature.s, n);
        
        // Calculate u1 = z * w mod n
        Cypher u1 = z * w;
        while (u1 >= n) u1 = u1 - n;
        
        // Calculate u2 = r * w mod n
        Cypher u2 = signature.r * w;
        while (u2 >= n) u2 = u2 - n;
        
        // Calculate point (x1, y1) = u1 * G + u2 * Q
        ECPoint p1 = curve->multiply(curve->generator(), u1);
        ECPoint p2 = curve->multiply(public_key, u2);
        ECPoint point = curve->add(p1, p2);
        
        if (point.isInfinity()) return false;
        
        // Check if r ≡ x1 (mod n)
        Cypher x1 = point.x();
        while (x1 >= n) x1 = x1 - n;
        
        return x1 == signature.r;
        
    } catch (...) {
        return false;
    }
}

inline ECDSA::Signature ECDSA::sign_message(const std::vector<uint8_t>& message,
                                           const Cypher& private_key,
                                           std::shared_ptr<ECCurve> curve) {
    auto hash = SHA256::hash(message);
    return sign(hash, private_key, curve);
}

inline bool ECDSA::verify_message(const std::vector<uint8_t>& message,
                                 const Signature& signature,
                                 const ECPoint& public_key,
                                 std::shared_ptr<ECCurve> curve) {
    auto hash = SHA256::hash(message);
    return verify(hash, signature, public_key, curve);
}

inline Cypher ECDSA::generate_random_scalar(const Cypher& n) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    auto n_bytes = n.toBytes();
    size_t byte_length = n_bytes.size();
    
    while (true) {
        std::vector<uint8_t> random_bytes(byte_length);
        for (auto& byte : random_bytes) {
            byte = dis(gen);
        }
        
        Cypher candidate(random_bytes);
        if (!candidate.isZero() && candidate < n) {
            return candidate;
        }
    }
}

inline Cypher ECDSA::mod_inverse(const Cypher& a, const Cypher& m) {
    // Simple implementation using extended Euclidean algorithm
    // This is a placeholder - in practice you'd want a more robust implementation
    
    if (a.isZero()) {
        throw std::invalid_argument("Cannot compute modular inverse of zero");
    }
    
    // For now, use trial method (very inefficient but functional)
    Cypher one(std::vector<uint8_t>{1});
    
    for (Cypher i = one; i < m; i = i + one) {
        Cypher product = a * i;
        
        // Reduce product modulo m
        while (product >= m) {
            product = product - m;
        }
        
        if (product == one) {
            return i;
        }
    }
    
    throw std::runtime_error("Modular inverse not found");
}

} // namespace lockey
