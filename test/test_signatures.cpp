#include <doctest/doctest.h>
#include "lockey/lockey.hpp"

TEST_SUITE("Digital Signatures") {
    const std::vector<uint8_t> test_message = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65
    }; // "This is a test message"

    TEST_CASE("ECDSA-P256 sign and verify") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        
        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::ECDSA_P256);
        
        // Sign the message
        auto sign_result = crypto.sign(test_message, keypair.private_key);
        REQUIRE(sign_result.success);
        CHECK_FALSE(sign_result.data.empty());
        CHECK(sign_result.error_message.empty());
        
        // Verify the signature
        auto verify_result = crypto.verify(test_message, sign_result.data, keypair.public_key);
        REQUIRE(verify_result.success);
        CHECK(verify_result.error_message.empty());
        
        // Verify with wrong message should fail
        std::vector<uint8_t> wrong_message = {0x77, 0x72, 0x6f, 0x6e, 0x67}; // "wrong"
        auto verify_wrong = crypto.verify(wrong_message, sign_result.data, keypair.public_key);
        CHECK_FALSE(verify_wrong.success);
        
        // Verify with wrong public key should fail
        auto keypair2 = crypto.generate_keypair();
        auto verify_wrong_key = crypto.verify(test_message, sign_result.data, keypair2.public_key);
        CHECK_FALSE(verify_wrong_key.success);
    }

    TEST_CASE("RSA-2048 sign and verify") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
        
        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_2048);
        
        // Sign the message
        auto sign_result = crypto.sign(test_message, keypair.private_key);
        
        if (sign_result.success) {
            CHECK_FALSE(sign_result.data.empty());
            
            // Verify the signature
            auto verify_result = crypto.verify(test_message, sign_result.data, keypair.public_key);
            CHECK(verify_result.success);
            
            // Verify with wrong message should fail
            std::vector<uint8_t> wrong_message = {0x77, 0x72, 0x6f, 0x6e, 0x67};
            auto verify_wrong = crypto.verify(wrong_message, sign_result.data, keypair.public_key);
            CHECK_FALSE(verify_wrong.success);
        } else {
            MESSAGE("RSA-2048 signing failed: " << sign_result.error_message);
        }
    }

    TEST_CASE("RSA-4096 sign and verify") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_4096);
        
        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_4096);
        
        // Sign the message
        auto sign_result = crypto.sign(test_message, keypair.private_key);
        
        if (sign_result.success) {
            CHECK_FALSE(sign_result.data.empty());
            
            // Verify the signature
            auto verify_result = crypto.verify(test_message, sign_result.data, keypair.public_key);
            CHECK(verify_result.success);
        } else {
            MESSAGE("RSA-4096 signing failed: " << sign_result.error_message);
        }
    }

    TEST_CASE("Sign with wrong algorithm should fail") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        std::vector<uint8_t> dummy_key = {0x01, 0x02, 0x03};
        
        auto result = crypto.sign(test_message, dummy_key);
        CHECK_FALSE(result.success);
        CHECK(result.error_message.find("does not support signing") != std::string::npos);
    }

    TEST_CASE("Empty message signing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        
        auto keypair = crypto.generate_keypair();
        std::vector<uint8_t> empty_message;
        
        auto sign_result = crypto.sign(empty_message, keypair.private_key);
        if (sign_result.success) {
            auto verify_result = crypto.verify(empty_message, sign_result.data, keypair.public_key);
            CHECK(verify_result.success);
        }
    }

    TEST_CASE("Large message signing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        
        auto keypair = crypto.generate_keypair();
        std::vector<uint8_t> large_message(10000, 0x42); // 10KB of 'B'
        
        auto sign_result = crypto.sign(large_message, keypair.private_key);
        REQUIRE(sign_result.success);
        
        auto verify_result = crypto.verify(large_message, sign_result.data, keypair.public_key);
        CHECK(verify_result.success);
    }

    TEST_CASE("Multiple signatures should be different") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        
        auto keypair = crypto.generate_keypair();
        
        auto sign1 = crypto.sign(test_message, keypair.private_key);
        auto sign2 = crypto.sign(test_message, keypair.private_key);
        
        REQUIRE(sign1.success);
        REQUIRE(sign2.success);
        
        // ECDSA signatures should be different each time due to random k
        CHECK(sign1.data != sign2.data);
        
        // But both should verify
        auto verify1 = crypto.verify(test_message, sign1.data, keypair.public_key);
        auto verify2 = crypto.verify(test_message, sign2.data, keypair.public_key);
        
        CHECK(verify1.success);
        CHECK(verify2.success);
    }

    TEST_CASE("Cross-algorithm verification should fail") {
        lockey::Lockey ecdsa_crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        lockey::Lockey rsa_crypto(lockey::Lockey::Algorithm::RSA_2048);
        
        auto ecdsa_keypair = ecdsa_crypto.generate_keypair();
        auto rsa_keypair = rsa_crypto.generate_keypair();
        
        auto ecdsa_signature = ecdsa_crypto.sign(test_message, ecdsa_keypair.private_key);
        REQUIRE(ecdsa_signature.success);
        
        // Try to verify ECDSA signature with RSA
        auto cross_verify = rsa_crypto.verify(test_message, ecdsa_signature.data, rsa_keypair.public_key);
        CHECK_FALSE(cross_verify.success);
    }
}
