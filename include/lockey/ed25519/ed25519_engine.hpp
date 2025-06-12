#pragma once

#include "../ec/engines.hpp"
#include "ed25519.hpp"

namespace lockey {
    namespace ed25519 {

        /**
         * @brief Ed25519 engine for integration with the main library
         */
        class Ed25519Engine : public ec::ECEngine {
          private:
            Ed25519 ed25519_;

          public:
            Ed25519Engine() = default;
            ~Ed25519Engine() = default;

            ec::KeyPair generate_keypair() override {
                auto ed_keypair = ed25519_.generate_keypair();

                ec::KeyPair result;
                result.private_key = ed_keypair.private_key;

                // Convert Ed25519 public key (32 bytes) to EC Point format
                // For Ed25519, we'll use the 32-byte key as the x-coordinate
                // and set y to zero (this is a simplified mapping)
                ec::Point public_point;
                public_point.x = ed_keypair.public_key;
                public_point.y = std::vector<uint8_t>(32, 0); // 32 bytes of zeros
                public_point.is_infinity = false;
                result.public_key = public_point;

                return result;
            }

            std::vector<uint8_t> sign(const std::vector<uint8_t> &hash,
                                      const std::vector<uint8_t> &private_key) override {
                auto signature = ed25519_.sign(hash, private_key);
                return signature.signature;
            }

            bool verify(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &signature,
                        const std::vector<uint8_t> &public_key) override {
                if (signature.size() != Ed25519::signature_size()) {
                    return false;
                }

                Ed25519Signature ed_signature;
                ed_signature.signature = signature;

                // If public_key is encoded as a Point (65 bytes: 0x04 + 32 + 32), extract x-coordinate
                std::vector<uint8_t> ed25519_public_key;
                if (public_key.size() == 65 && public_key[0] == 0x04) {
                    // Extract x-coordinate (the actual Ed25519 public key)
                    ed25519_public_key.assign(public_key.begin() + 1, public_key.begin() + 33);
                } else if (public_key.size() == 32) {
                    // Direct 32-byte Ed25519 public key
                    ed25519_public_key = public_key;
                } else {
                    return false; // Invalid public key format
                }

                return ed25519_.verify(hash, ed_signature, ed25519_public_key);
            }

            std::vector<uint8_t> ecdh(const std::vector<uint8_t> &private_key,
                                      const std::vector<uint8_t> &public_key) override {
                // Ed25519 doesn't directly support ECDH, but we can simulate it
                // In practice, you'd use X25519 for ECDH
                throw std::runtime_error("ECDH not supported with Ed25519 (use X25519 instead)");
            }
        };

    } // namespace ed25519
} // namespace lockey
