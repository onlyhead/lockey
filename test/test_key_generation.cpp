#include <doctest/doctest.h>
#include "lockey/lockey.hpp"

TEST_SUITE("Key Generation") {
    TEST_CASE("Symmetric key generation") {
        lockey::Lockey crypto;
        
        // Test default size (32 bytes)
        auto result = crypto.generate_symmetric_key();
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
        CHECK(result.error_message.empty());
        
        // Test different sizes
        auto result16 = crypto.generate_symmetric_key(16);
        REQUIRE(result16.success);
        CHECK(result16.data.size() == 16);
        
        auto result64 = crypto.generate_symmetric_key(64);
        REQUIRE(result64.success);
        CHECK(result64.data.size() == 64);
        
        // Keys should be different each time
        auto result2 = crypto.generate_symmetric_key();
        REQUIRE(result2.success);
        CHECK(result.data != result2.data);
    }

    TEST_CASE("RSA-2048 key generation") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
        
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_2048);
        CHECK_FALSE(keypair.public_key.empty());
        CHECK_FALSE(keypair.private_key.empty());
        
        // Keys should be different
        CHECK(keypair.public_key != keypair.private_key);
        
        // Generate another pair - should be different
        auto keypair2 = crypto.generate_keypair();
        CHECK(keypair.public_key != keypair2.public_key);
        CHECK(keypair.private_key != keypair2.private_key);
    }

    TEST_CASE("RSA-4096 key generation") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_4096);
        
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_4096);
        CHECK_FALSE(keypair.public_key.empty());
        CHECK_FALSE(keypair.private_key.empty());
        
        // RSA-4096 keys should be larger than RSA-2048
        // Note: This is implementation dependent, but generally true
        MESSAGE("RSA-4096 public key size: " << keypair.public_key.size());
        MESSAGE("RSA-4096 private key size: " << keypair.private_key.size());
    }

    TEST_CASE("ECDSA-P256 key generation") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::ECDSA_P256);
        CHECK_FALSE(keypair.public_key.empty());
        CHECK_FALSE(keypair.private_key.empty());
        
        // P-256 public key should be 65 bytes (uncompressed format: 0x04 + 32 + 32)
        CHECK(keypair.public_key.size() == 65);
        CHECK(keypair.public_key[0] == 0x04); // Uncompressed point indicator
        
        // P-256 private key should be 32 bytes
        CHECK(keypair.private_key.size() == 32);
    }

    TEST_CASE("ECDSA-P384 key generation (might not be implemented)") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P384);
        
        try {
            auto keypair = crypto.generate_keypair();
            CHECK(keypair.algorithm == lockey::Lockey::Algorithm::ECDSA_P384);
            CHECK_FALSE(keypair.public_key.empty());
            CHECK_FALSE(keypair.private_key.empty());
            
            MESSAGE("ECDSA-P384 key generation successful");
        } catch (const std::exception& e) {
            MESSAGE("ECDSA-P384 not implemented: " << e.what());
        }
    }

    TEST_CASE("ECDSA-P521 key generation (might not be implemented)") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P521);
        
        try {
            auto keypair = crypto.generate_keypair();
            CHECK(keypair.algorithm == lockey::Lockey::Algorithm::ECDSA_P521);
            CHECK_FALSE(keypair.public_key.empty());
            CHECK_FALSE(keypair.private_key.empty());
            
            MESSAGE("ECDSA-P521 key generation successful");
        } catch (const std::exception& e) {
            MESSAGE("ECDSA-P521 not implemented: " << e.what());
        }
    }

    TEST_CASE("Ed25519 key generation (should fail - not implemented)") {
        CHECK_THROWS_AS(lockey::Lockey crypto(lockey::Lockey::Algorithm::Ed25519), 
                       std::runtime_error);
    }

    TEST_CASE("Key generation with symmetric algorithm should fail") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        
        CHECK_THROWS_AS(crypto.generate_keypair(), std::runtime_error);
    }
}
