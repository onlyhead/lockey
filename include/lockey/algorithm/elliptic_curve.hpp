#pragma once
#include "cypher.hpp"
#include "../utils/modular_arithmetic.hpp"
#include <vector>
#include <cstdint>
#include <memory>

namespace lockey {

// Forward declarations
class ECPoint;
class ECCurve;

/**
 * @brief Elliptic Curve Point representation
 * 
 * Represents a point on an elliptic curve in affine coordinates (x, y)
 * or the point at infinity.
 */
class ECPoint {
private:
    Cypher x_, y_;
    bool is_infinity_;
    const ECCurve* curve_;

public:
    ECPoint() : is_infinity_(true), curve_(nullptr) {}
    
    ECPoint(const Cypher& x, const Cypher& y) 
        : x_(x), y_(y), is_infinity_(false), curve_(nullptr) {}
        
    ECPoint(const Cypher& x, const Cypher& y, const ECCurve* curve)
        : x_(x), y_(y), is_infinity_(false), curve_(curve) {}
        
    ECPoint(const ECCurve* curve) : is_infinity_(true), curve_(curve) {}
    
    static ECPoint infinity() {
        return ECPoint();
    }
    
    bool isInfinity() const { return is_infinity_; }
    const Cypher& x() const { return x_; }
    const Cypher& y() const { return y_; }
    
    // Point addition
    ECPoint operator+(const ECPoint& other) const;
    
    // Point doubling (special case of addition)
    ECPoint double_point() const;
    
    // Scalar multiplication
    ECPoint operator*(const Cypher& scalar) const;
    
    // Equality comparison
    bool operator==(const ECPoint& other) const;
    bool operator!=(const ECPoint& other) const { return !(*this == other); }
    
    // Encoding/decoding
    std::vector<uint8_t> encode(bool compressed = false) const;
    static ECPoint decode(const std::vector<uint8_t>& data);
    
    friend class ECCurve;
    friend class Secp256r1;
    friend class Secp384r1;
};

/**
 * @brief Abstract base class for elliptic curves
 * 
 * Defines the interface for elliptic curve operations.
 */
class ECCurve {
public:
    virtual ~ECCurve() = default;
    
    // Curve parameters
    virtual const Cypher& p() const = 0;  // Field prime
    virtual const Cypher& a() const = 0;  // Curve parameter a
    virtual const Cypher& b() const = 0;  // Curve parameter b
    virtual const Cypher& n() const = 0;  // Order of base point
    virtual const ECPoint& g() const = 0; // Base point (generator)
    
    // Curve identification
    virtual std::string name() const = 0;
    virtual int curve_id() const = 0;
    
    // Convenience accessors
    const Cypher& order() const { return n(); }
    const ECPoint& generator() const { return g(); }
    
    // Point operations on this curve
    virtual ECPoint add(const ECPoint& p1, const ECPoint& p2) const = 0;
    virtual ECPoint double_point(const ECPoint& point) const = 0;
    virtual ECPoint multiply(const ECPoint& point, const Cypher& scalar) const = 0;
    virtual bool is_on_curve(const ECPoint& point) const = 0;
    
    // Key generation
    virtual ECPoint generate_public_key(const Cypher& private_key) const = 0;
    
    // Point encoding/decoding for this curve
    virtual std::vector<uint8_t> encode_point(const ECPoint& point, bool compressed = false) const = 0;
    virtual ECPoint decode_point(const std::vector<uint8_t>& data) const = 0;
    
    // Coordinate size in bytes
    virtual size_t coordinate_size() const = 0;
};

/**
 * @brief secp256r1 (NIST P-256) curve implementation
 */
class Secp256r1 : public ECCurve {
private:
    static const Cypher p_;     // Field prime
    static const Cypher a_;     // Curve parameter a (-3)
    static const Cypher b_;     // Curve parameter b
    static const Cypher n_;     // Order of base point
    static const ECPoint g_;    // Base point
    
public:
    static std::shared_ptr<Secp256r1> instance();
    
    const Cypher& p() const override { return p_; }
    const Cypher& a() const override { return a_; }
    const Cypher& b() const override { return b_; }
    const Cypher& n() const override { return n_; }
    const ECPoint& g() const override { return g_; }
    
    std::string name() const override { return "secp256r1"; }
    int curve_id() const override { return 23; } // NIST P-256
    
    ECPoint add(const ECPoint& p1, const ECPoint& p2) const override;
    ECPoint double_point(const ECPoint& point) const override;
    ECPoint multiply(const ECPoint& point, const Cypher& scalar) const override;
    bool is_on_curve(const ECPoint& point) const override;
    
    ECPoint generate_public_key(const Cypher& private_key) const override;
    
    std::vector<uint8_t> encode_point(const ECPoint& point, bool compressed = false) const override;
    ECPoint decode_point(const std::vector<uint8_t>& data) const override;
    
    size_t coordinate_size() const override { return 32; } // 256 bits = 32 bytes
};

/**
 * @brief secp384r1 (NIST P-384) curve implementation
 */
class Secp384r1 : public ECCurve {
private:
    static const Cypher p_;     // Field prime
    static const Cypher a_;     // Curve parameter a (-3)
    static const Cypher b_;     // Curve parameter b
    static const Cypher n_;     // Order of base point
    static const ECPoint g_;    // Base point
    
public:
    static std::shared_ptr<Secp384r1> instance();
    
    const Cypher& p() const override { return p_; }
    const Cypher& a() const override { return a_; }
    const Cypher& b() const override { return b_; }
    const Cypher& n() const override { return n_; }
    const ECPoint& g() const override { return g_; }
    
    std::string name() const override { return "secp384r1"; }
    int curve_id() const override { return 24; } // NIST P-384
    
    ECPoint add(const ECPoint& p1, const ECPoint& p2) const override;
    ECPoint double_point(const ECPoint& point) const override;
    ECPoint multiply(const ECPoint& point, const Cypher& scalar) const override;
    bool is_on_curve(const ECPoint& point) const override;
    
    ECPoint generate_public_key(const Cypher& private_key) const override;
    
    std::vector<uint8_t> encode_point(const ECPoint& point, bool compressed = false) const override;
    ECPoint decode_point(const std::vector<uint8_t>& data) const override;
    
    size_t coordinate_size() const override { return 48; } // 384 bits = 48 bytes
};

// ===== Static member definitions =====
inline const Cypher Secp256r1::p_(std::vector<uint8_t>{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
});

inline const Cypher Secp256r1::a_(std::vector<uint8_t>{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
});

inline const Cypher Secp256r1::b_(std::vector<uint8_t>{
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
});

inline const Cypher Secp256r1::n_(std::vector<uint8_t>{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
});

inline const ECPoint Secp256r1::g_(
    Cypher(std::vector<uint8_t>{
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
    }),
    Cypher(std::vector<uint8_t>{
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    })
);

inline const Cypher Secp384r1::p_(std::vector<uint8_t>{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
});

inline const Cypher Secp384r1::a_(std::vector<uint8_t>{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
});

inline const Cypher Secp384r1::b_(std::vector<uint8_t>{
    0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
    0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
    0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
});

inline const Cypher Secp384r1::n_(std::vector<uint8_t>{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
});

inline const ECPoint Secp384r1::g_(
    Cypher(std::vector<uint8_t>{
        0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
        0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
        0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
    }),
    Cypher(std::vector<uint8_t>{
        0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
        0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
        0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F
    })
);

// ===== Implementations =====

inline std::shared_ptr<Secp256r1> Secp256r1::instance() {
    static auto inst = std::make_shared<Secp256r1>();
    return inst;
}

inline std::shared_ptr<Secp384r1> Secp384r1::instance() {
    static auto inst = std::make_shared<Secp384r1>();
    return inst;
}

// Secp256r1 point operations
inline ECPoint Secp256r1::add(const ECPoint& p1, const ECPoint& p2) const {
    using utils::ModularArithmetic;
    
    if (p1.isInfinity()) return p2;
    if (p2.isInfinity()) return p1;
    
    if (p1 == p2) {
        return double_point(p1);
    }
    
    // Check if points are additive inverses
    if (p1.x() == p2.x()) {
        // If x coordinates are same but points are different, they must be additive inverses
        return ECPoint(); // Point at infinity
    }
    
    // Point addition formula: P1 + P2 = P3
    // λ = (y2 - y1) / (x2 - x1)
    // x3 = λ² - x1 - x2
    // y3 = λ(x1 - x3) - y1
    
    Cypher dx = ModularArithmetic::mod_sub(p2.x(), p1.x(), p_);
    Cypher dy = ModularArithmetic::mod_sub(p2.y(), p1.y(), p_);
    
    Cypher lambda = ModularArithmetic::mod_div(dy, dx, p_);
    
    Cypher x3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_sub(
            ModularArithmetic::mod_square(lambda, p_), 
            p1.x(), p_
        ), 
        p2.x(), p_
    );
    
    Cypher y3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_mul(
            lambda, 
            ModularArithmetic::mod_sub(p1.x(), x3, p_), 
            p_
        ), 
        p1.y(), p_
    );
    
    return ECPoint(x3, y3, this);
}

inline ECPoint Secp256r1::double_point(const ECPoint& point) const {
    using utils::ModularArithmetic;
    
    if (point.isInfinity()) return point;
    
    // Point doubling formula: 2P = P3
    // λ = (3x₁² + a) / (2y₁)
    // x₃ = λ² - 2x₁
    // y₃ = λ(x₁ - x₃) - y₁
    
    Cypher three(3u);
    Cypher two(2u);
    
    Cypher numerator = ModularArithmetic::mod_add(
        ModularArithmetic::mod_mul(
            three, 
            ModularArithmetic::mod_square(point.x(), p_), 
            p_
        ), 
        a_, p_
    );
    
    Cypher denominator = ModularArithmetic::mod_mul(two, point.y(), p_);
    
    Cypher lambda = ModularArithmetic::mod_div(numerator, denominator, p_);
    
    Cypher x3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_square(lambda, p_), 
        ModularArithmetic::mod_mul(two, point.x(), p_), 
        p_
    );
    
    Cypher y3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_mul(
            lambda, 
            ModularArithmetic::mod_sub(point.x(), x3, p_), 
            p_
        ), 
        point.y(), p_
    );
    
    return ECPoint(x3, y3, this);
}

inline ECPoint Secp256r1::multiply(const ECPoint& point, const Cypher& scalar) const {
    if (point.isInfinity()) return point;
    
    Cypher zero(0u);
    if (scalar == zero) return ECPoint(); // Point at infinity
    
    // Binary method (double-and-add)
    ECPoint result; // Point at infinity
    ECPoint addend = point;
    
    Cypher k = scalar;
    while (!k.isZero()) {
        if (k.getLowLimb() & 1) { // If k is odd
            if (result.isInfinity()) {
                result = addend;
            } else {
                result = add(result, addend);
            }
        }
        addend = double_point(addend);
        k = k >> 1; // Right shift to divide by 2
    }
    
    return result;
}

inline bool Secp256r1::is_on_curve(const ECPoint& point) const {
    using utils::ModularArithmetic;
    
    if (point.isInfinity()) return true;
    
    // Check if y² ≡ x³ + ax + b (mod p)
    Cypher y_squared = ModularArithmetic::mod_square(point.y(), p_);
    
    Cypher x_cubed = ModularArithmetic::mod_mul(
        ModularArithmetic::mod_square(point.x(), p_), 
        point.x(), p_
    );
    
    Cypher ax = ModularArithmetic::mod_mul(a_, point.x(), p_);
    
    Cypher right_side = ModularArithmetic::mod_add(
        ModularArithmetic::mod_add(x_cubed, ax, p_), 
        b_, p_
    );
    
    return y_squared == right_side;
}

inline ECPoint Secp256r1::generate_public_key(const Cypher& private_key) const {
    return multiply(g_, private_key);
}

inline std::vector<uint8_t> Secp256r1::encode_point(const ECPoint& point, bool compressed) const {
    if (point.isInfinity()) {
        return {0x00}; // Point at infinity
    }
    
    auto x_bytes = point.x().toBytes();
    auto y_bytes = point.y().toBytes();
    
    // Pad to coordinate size
    while (x_bytes.size() < coordinate_size()) x_bytes.insert(x_bytes.begin(), 0);
    while (y_bytes.size() < coordinate_size()) y_bytes.insert(y_bytes.begin(), 0);
    
    if (compressed) {
        std::vector<uint8_t> result;
        result.push_back(0x02 + (y_bytes.back() & 1)); // 0x02 for even y, 0x03 for odd y
        result.insert(result.end(), x_bytes.begin(), x_bytes.end());
        return result;
    } else {
        std::vector<uint8_t> result;
        result.push_back(0x04); // Uncompressed point marker
        result.insert(result.end(), x_bytes.begin(), x_bytes.end());
        result.insert(result.end(), y_bytes.begin(), y_bytes.end());
        return result;
    }
}

inline ECPoint Secp256r1::decode_point(const std::vector<uint8_t>& data) const {
    if (data.empty()) {
        throw std::invalid_argument("Empty point data");
    }
    
    if (data[0] == 0x00) {
        return ECPoint(); // Point at infinity
    }
    
    if (data[0] == 0x04) { // Uncompressed
        if (data.size() != 1 + 2 * coordinate_size()) {
            throw std::invalid_argument("Invalid uncompressed point size");
        }
        
        std::vector<uint8_t> x_bytes(data.begin() + 1, data.begin() + 1 + coordinate_size());
        std::vector<uint8_t> y_bytes(data.begin() + 1 + coordinate_size(), data.end());
        
        ECPoint point(Cypher(x_bytes), Cypher(y_bytes), this);
        
        if (!is_on_curve(point)) {
            throw std::invalid_argument("Point is not on curve");
        }
        
        return point;
    }
    
    throw std::invalid_argument("Compressed point decoding not yet implemented");
}

// Similar implementations for Secp384r1
inline ECPoint Secp384r1::add(const ECPoint& p1, const ECPoint& p2) const {
    using utils::ModularArithmetic;
    
    if (p1.isInfinity()) return p2;
    if (p2.isInfinity()) return p1;
    
    if (p1 == p2) {
        return double_point(p1);
    }
    
    if (p1.x() == p2.x()) {
        return ECPoint(); // Point at infinity
    }
    
    Cypher dx = ModularArithmetic::mod_sub(p2.x(), p1.x(), p_);
    Cypher dy = ModularArithmetic::mod_sub(p2.y(), p1.y(), p_);
    
    Cypher lambda = ModularArithmetic::mod_div(dy, dx, p_);
    
    Cypher x3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_sub(
            ModularArithmetic::mod_square(lambda, p_), 
            p1.x(), p_
        ), 
        p2.x(), p_
    );
    
    Cypher y3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_mul(
            lambda, 
            ModularArithmetic::mod_sub(p1.x(), x3, p_), 
            p_
        ), 
        p1.y(), p_
    );
    
    return ECPoint(x3, y3, this);
}

inline ECPoint Secp384r1::double_point(const ECPoint& point) const {
    using utils::ModularArithmetic;
    
    if (point.isInfinity()) return point;
    
    Cypher three(3u);
    Cypher two(2u);
    
    Cypher numerator = ModularArithmetic::mod_add(
        ModularArithmetic::mod_mul(
            three, 
            ModularArithmetic::mod_square(point.x(), p_), 
            p_
        ), 
        a_, p_
    );
    
    Cypher denominator = ModularArithmetic::mod_mul(two, point.y(), p_);
    
    Cypher lambda = ModularArithmetic::mod_div(numerator, denominator, p_);
    
    Cypher x3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_square(lambda, p_), 
        ModularArithmetic::mod_mul(two, point.x(), p_), 
        p_
    );
    
    Cypher y3 = ModularArithmetic::mod_sub(
        ModularArithmetic::mod_mul(
            lambda, 
            ModularArithmetic::mod_sub(point.x(), x3, p_), 
            p_
        ), 
        point.y(), p_
    );
    
    return ECPoint(x3, y3, this);
}

inline ECPoint Secp384r1::multiply(const ECPoint& point, const Cypher& scalar) const {
    if (point.isInfinity()) return point;
    
    Cypher zero(0u);
    if (scalar == zero) return ECPoint();
    
    ECPoint result;
    ECPoint addend = point;
    
    Cypher k = scalar;
    while (!k.isZero()) {
        if (k.getLowLimb() & 1) {
            if (result.isInfinity()) {
                result = addend;
            } else {
                result = add(result, addend);
            }
        }
        addend = double_point(addend);
        k = k >> 1;
    }
    
    return result;
}

inline bool Secp384r1::is_on_curve(const ECPoint& point) const {
    using utils::ModularArithmetic;
    
    if (point.isInfinity()) return true;
    
    Cypher y_squared = ModularArithmetic::mod_square(point.y(), p_);
    
    Cypher x_cubed = ModularArithmetic::mod_mul(
        ModularArithmetic::mod_square(point.x(), p_), 
        point.x(), p_
    );
    
    Cypher ax = ModularArithmetic::mod_mul(a_, point.x(), p_);
    
    Cypher right_side = ModularArithmetic::mod_add(
        ModularArithmetic::mod_add(x_cubed, ax, p_), 
        b_, p_
    );
    
    return y_squared == right_side;
}

inline ECPoint Secp384r1::generate_public_key(const Cypher& private_key) const {
    return multiply(g_, private_key);
}

inline std::vector<uint8_t> Secp384r1::encode_point(const ECPoint& point, bool compressed) const {
    if (point.isInfinity()) {
        return {0x00};
    }
    
    auto x_bytes = point.x().toBytes();
    auto y_bytes = point.y().toBytes();
    
    while (x_bytes.size() < coordinate_size()) x_bytes.insert(x_bytes.begin(), 0);
    while (y_bytes.size() < coordinate_size()) y_bytes.insert(y_bytes.begin(), 0);
    
    if (compressed) {
        std::vector<uint8_t> result;
        result.push_back(0x02 + (y_bytes.back() & 1));
        result.insert(result.end(), x_bytes.begin(), x_bytes.end());
        return result;
    } else {
        std::vector<uint8_t> result;
        result.push_back(0x04);
        result.insert(result.end(), x_bytes.begin(), x_bytes.end());
        result.insert(result.end(), y_bytes.begin(), y_bytes.end());
        return result;
    }
}

inline ECPoint Secp384r1::decode_point(const std::vector<uint8_t>& data) const {
    if (data.empty()) {
        throw std::invalid_argument("Empty point data");
    }
    
    if (data[0] == 0x00) {
        return ECPoint();
    }
    
    if (data[0] == 0x04) {
        if (data.size() != 1 + 2 * coordinate_size()) {
            throw std::invalid_argument("Invalid uncompressed point size");
        }
        
        std::vector<uint8_t> x_bytes(data.begin() + 1, data.begin() + 1 + coordinate_size());
        std::vector<uint8_t> y_bytes(data.begin() + 1 + coordinate_size(), data.end());
        
        ECPoint point(Cypher(x_bytes), Cypher(y_bytes), this);
        
        if (!is_on_curve(point)) {
            throw std::invalid_argument("Point is not on curve");
        }
        
        return point;
    }
    
    throw std::invalid_argument("Compressed point decoding not yet implemented");
}

// ECPoint implementations
inline bool ECPoint::operator==(const ECPoint& other) const {
    if (is_infinity_ && other.is_infinity_) return true;
    if (is_infinity_ || other.is_infinity_) return false;
    return x_ == other.x_ && y_ == other.y_;
}

} // namespace lockey
