#pragma once

#include "../utils/common.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace lockey {
    namespace ed25519 {

        /**
         * @brief Ed25519 signature
         */
        struct Ed25519Signature {
            std::vector<uint8_t> signature; // 64 bytes: R (32 bytes) + S (32 bytes)
        };

        /**
         * @brief Ed25519 key pair
         */
        struct Ed25519KeyPair {
            std::vector<uint8_t> private_key; // 32 bytes seed
            std::vector<uint8_t> public_key;  // 32 bytes
        };

        /**
         * @brief Ed25519 signature algorithm implementation
         *
         * This is a simplified implementation for educational purposes.
         * In production, use a well-tested cryptographic library.
         */
        class Ed25519 {
          private:
            static constexpr size_t PRIVATE_KEY_SIZE = 32;
            static constexpr size_t PUBLIC_KEY_SIZE = 32;
            static constexpr size_t SIGNATURE_SIZE = 64;

            // Ed25519 curve parameters
            // Prime: 2^255 - 19
            static constexpr std::array<uint8_t, 32> ED25519_PRIME = {
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

            // Base point order
            static constexpr std::array<uint8_t, 32> ED25519_ORDER = {
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed};

          public:
            Ed25519() = default;
            ~Ed25519() = default;

            // Core operations
            Ed25519KeyPair generate_keypair() const;
            Ed25519Signature sign(const std::vector<uint8_t> &message, const std::vector<uint8_t> &private_key) const;
            bool verify(const std::vector<uint8_t> &message, const Ed25519Signature &signature,
                        const std::vector<uint8_t> &public_key) const;

            // Key derivation
            std::vector<uint8_t> derive_public_key(const std::vector<uint8_t> &private_key) const;

            // Utility methods
            static constexpr size_t private_key_size() { return PRIVATE_KEY_SIZE; }
            static constexpr size_t public_key_size() { return PUBLIC_KEY_SIZE; }
            static constexpr size_t signature_size() { return SIGNATURE_SIZE; }

          private:
            // Helper functions for modular arithmetic
            void mod_add(std::vector<uint8_t> &result, const std::vector<uint8_t> &a,
                         const std::vector<uint8_t> &b) const;
            void mod_mul(std::vector<uint8_t> &result, const std::vector<uint8_t> &a,
                         const std::vector<uint8_t> &b) const;
            void mod_exp(std::vector<uint8_t> &result, const std::vector<uint8_t> &base,
                         const std::vector<uint8_t> &exp) const;

            // Hash function (using the system's SHA-512 equivalent)
            std::vector<uint8_t> hash_function(const std::vector<uint8_t> &data) const;

            // Random number generation
            std::vector<uint8_t> generate_random_bytes(size_t count) const;
        };

    } // namespace ed25519
} // namespace lockey
