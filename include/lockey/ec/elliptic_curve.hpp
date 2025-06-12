#pragma once

#include "../utils/common.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace lockey {
    namespace ec {

        /**
         * @brief Elliptic curve point representation
         */
        struct Point {
            std::vector<uint8_t> x;
            std::vector<uint8_t> y;
            bool is_infinity = false;

            Point() = default;
            Point(const std::vector<uint8_t> &x_coord, const std::vector<uint8_t> &y_coord) : x(x_coord), y(y_coord) {}
            Point(const std::vector<uint8_t> &x_coord, const std::vector<uint8_t> &y_coord, bool infinity)
                : x(x_coord), y(y_coord), is_infinity(infinity) {}

            bool operator==(const Point &other) const {
                return is_infinity == other.is_infinity && x == other.x && y == other.y;
            }
        };

        /**
         * @brief ECDSA signature
         */
        struct Signature {
            std::vector<uint8_t> r;
            std::vector<uint8_t> s;

            Signature() = default;
            Signature(const std::vector<uint8_t> &r_val, const std::vector<uint8_t> &s_val) : r(r_val), s(s_val) {}
        };

        /**
         * @brief EC Key pair structure
         */
        struct KeyPair {
            std::vector<uint8_t> private_key;
            Point public_key;

            KeyPair() = default;
            KeyPair(const std::vector<uint8_t> &priv, const Point &pub) : private_key(priv), public_key(pub) {}
        };

        // Type aliases for compatibility with implementation
        using ECPoint = Point;
        using ECKeyPair = KeyPair;
        using ECDSASignature = Signature;

        /**
         * @brief Base elliptic curve interface
         */
        class CurveBase {
          public:
            virtual ~CurveBase() = default;

            // Curve parameters
            virtual size_t field_size() const = 0;
            virtual size_t order_size() const = 0;
            virtual std::string name() const = 0;

            // Point operations
            virtual Point point_add(const Point &p1, const Point &p2) const = 0;
            virtual Point point_multiply(const Point &point, const std::vector<uint8_t> &scalar) const = 0;
            virtual Point generator() const = 0;
            virtual bool is_on_curve(const Point &point) const = 0;

            // Key operations
            virtual std::vector<uint8_t> generate_private_key() const = 0;
            virtual Point compute_public_key(const std::vector<uint8_t> &private_key) const = 0;

            // Encoding/Decoding
            virtual std::vector<uint8_t> encode_point(const Point &point, bool compressed = false) const = 0;
            virtual Point decode_point(const std::vector<uint8_t> &encoded) const = 0;

            // ECDSA operations
            virtual Signature sign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &private_key) const = 0;
            virtual bool verify(const std::vector<uint8_t> &hash, const Signature &signature,
                                const Point &public_key) const = 0;
        };

        /**
         * @brief P-256 (secp256r1) curve implementation
         */
        class P256 : public CurveBase {
          public:
            // P-256 curve parameters
            static constexpr size_t FIELD_SIZE = 32;
            static constexpr size_t ORDER_SIZE = 32;

            // Field prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
            static const std::array<uint8_t, 32> P;

            // Curve order: n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
            static const std::array<uint8_t, 32> N;

            // Curve parameters: y^2 = x^3 - 3x + b
            static const std::array<uint8_t, 32> B;

            // Generator point
            static const std::array<uint8_t, 32> GX;
            static const std::array<uint8_t, 32> GY;

            // Modular arithmetic operations
            std::vector<uint8_t> mod_add(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_sub(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_mul(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_inv(const std::vector<uint8_t> &a, const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_exp(const std::vector<uint8_t> &base, const std::vector<uint8_t> &exp,
                                         const std::vector<uint8_t> &mod) const;

            bool is_zero(const std::vector<uint8_t> &a) const;
            int compare(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const;

          public:
            size_t field_size() const override { return FIELD_SIZE; }
            size_t order_size() const override { return ORDER_SIZE; }
            std::string name() const override { return "P-256"; }

            Point point_add(const Point &p1, const Point &p2) const override;
            Point point_multiply(const Point &point, const std::vector<uint8_t> &scalar) const override;
            Point point_double(const Point &point) const;
            Point generator() const override;
            bool is_on_curve(const Point &point) const override;

            std::vector<uint8_t> generate_private_key() const override;
            Point compute_public_key(const std::vector<uint8_t> &private_key) const override;

            std::vector<uint8_t> encode_point(const Point &point, bool compressed = false) const override;
            Point decode_point(const std::vector<uint8_t> &encoded) const override;

            Signature sign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &private_key) const override;
            bool verify(const std::vector<uint8_t> &hash, const Signature &signature,
                        const Point &public_key) const override;
        };

        /**
         * @brief P256Curve class for compatibility with implementation
         * Standalone class to avoid virtual table issues
         */
        class P256Curve {
          private:
            P256 p256_impl; // Use composition instead of inheritance

          public:
            // Core curve operations
            ECKeyPair generate_keypair() const;
            ECPoint point_add(const ECPoint &p1, const ECPoint &p2) const;
            ECPoint point_double(const ECPoint &p) const;
            ECPoint point_multiply(const ECPoint &p, const std::vector<uint8_t> &k) const;
            ECDSASignature sign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &private_key) const;
            bool verify(const std::vector<uint8_t> &hash, const ECDSASignature &signature,
                        const ECPoint &public_key) const;

            // Point encoding/decoding
            std::vector<uint8_t> encode_point(const ECPoint &point, bool compressed = false) const;
            ECPoint decode_point(const std::vector<uint8_t> &encoded) const;

            // Utility methods
            bool is_zero(const std::vector<uint8_t> &a) const;
            int compare(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const;

            // Modular arithmetic operations
            std::vector<uint8_t> mod_add(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_sub(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_mul(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_inv(const std::vector<uint8_t> &a, const std::vector<uint8_t> &mod) const;

            // Static curve parameters (references to P256 constants)
            static const std::array<uint8_t, 32> P;
            static const std::array<uint8_t, 32> N;
            static const std::array<uint8_t, 32> B;
            static const std::array<uint8_t, 32> GX;
            static const std::array<uint8_t, 32> GY;
        };

        /**
         * @brief P-384 (secp384r1) curve implementation
         */
        class P384 : public CurveBase {
          private:
            static constexpr size_t FIELD_SIZE = 48;
            static constexpr size_t ORDER_SIZE = 48;

            // Similar structure to P256 but with 384-bit parameters
            static const std::array<uint8_t, 48> P;
            static const std::array<uint8_t, 48> N;
            static const std::array<uint8_t, 48> B;
            static const std::array<uint8_t, 48> GX;
            static const std::array<uint8_t, 48> GY;

            // Modular arithmetic operations (similar to P256)
            std::vector<uint8_t> mod_add(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_sub(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_mul(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_inv(const std::vector<uint8_t> &a, const std::vector<uint8_t> &mod) const;
            bool is_zero(const std::vector<uint8_t> &a) const;
            int compare(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const;

          public:
            size_t field_size() const override { return FIELD_SIZE; }
            size_t order_size() const override { return ORDER_SIZE; }
            std::string name() const override { return "P-384"; }

            Point point_add(const Point &p1, const Point &p2) const override;
            Point point_multiply(const Point &point, const std::vector<uint8_t> &scalar) const override;
            Point generator() const override;
            bool is_on_curve(const Point &point) const override;

            std::vector<uint8_t> generate_private_key() const override;
            Point compute_public_key(const std::vector<uint8_t> &private_key) const override;

            std::vector<uint8_t> encode_point(const Point &point, bool compressed = false) const override;
            Point decode_point(const std::vector<uint8_t> &encoded) const override;

            Signature sign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &private_key) const override;
            bool verify(const std::vector<uint8_t> &hash, const Signature &signature,
                        const Point &public_key) const override;
        };

        /**
         * @brief P-521 (secp521r1) curve implementation
         */
        class P521 : public CurveBase {
          private:
            static constexpr size_t FIELD_SIZE = 66; // 521 bits = 66 bytes (rounded up)
            static constexpr size_t ORDER_SIZE = 66;

            static const std::array<uint8_t, 66> P;
            static const std::array<uint8_t, 66> N;
            static const std::array<uint8_t, 66> B;
            static const std::array<uint8_t, 66> GX;
            static const std::array<uint8_t, 66> GY;

            // Modular arithmetic operations
            std::vector<uint8_t> mod_add(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_sub(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_mul(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b,
                                         const std::vector<uint8_t> &mod) const;
            std::vector<uint8_t> mod_inv(const std::vector<uint8_t> &a, const std::vector<uint8_t> &mod) const;
            bool is_zero(const std::vector<uint8_t> &a) const;
            int compare(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const;

          public:
            size_t field_size() const override { return FIELD_SIZE; }
            size_t order_size() const override { return ORDER_SIZE; }
            std::string name() const override { return "P-521"; }

            Point point_add(const Point &p1, const Point &p2) const override;
            Point point_multiply(const Point &point, const std::vector<uint8_t> &scalar) const override;
            Point generator() const override;
            bool is_on_curve(const Point &point) const override;

            std::vector<uint8_t> generate_private_key() const override;
            Point compute_public_key(const std::vector<uint8_t> &private_key) const override;

            std::vector<uint8_t> encode_point(const Point &point, bool compressed = false) const override;
            Point decode_point(const std::vector<uint8_t> &encoded) const override;

            Signature sign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &private_key) const override;
            bool verify(const std::vector<uint8_t> &hash, const Signature &signature,
                        const Point &public_key) const override;
        };

    } // namespace ec
} // namespace lockey
