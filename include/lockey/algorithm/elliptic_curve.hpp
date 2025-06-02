#pragma once
#include "cypher.hpp"
#include "../utils/modular_arithmetic.hpp"
#include <vector>
#include <cstdint>
#include <memory>
#include <random>
#include <stdexcept>

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

public:
    ECPoint() : is_infinity_(true) {}
    
    ECPoint(const Cypher& x, const Cypher& y) 
        : x_(x), y_(y), is_infinity_(false) {}
    
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
    
private:
    friend class ECCurve;
    const ECCurve* curve_;
    
    ECPoint(const Cypher& x, const Cypher& y, const ECCurve* curve)
        : x_(x), y_(y), is_infinity_(false), curve_(curve) {}
        
    ECPoint(const ECCurve* curve) : is_infinity_(true), curve_(curve) {}
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

} // namespace lockey
