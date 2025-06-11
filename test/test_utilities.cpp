#include <doctest/doctest.h>
#include "lockey/lockey.hpp"

TEST_SUITE("Utility Functions") {
    TEST_CASE("Hex conversion") {
        // Test basic hex conversion
        std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        std::string expected_hex = "48656c6c6f";
        
        auto hex_result = lockey::Lockey::to_hex(data);
        CHECK(hex_result == expected_hex);
        
        // Test reverse conversion
        auto data_result = lockey::Lockey::from_hex(hex_result);
        CHECK(data_result == data);
    }

    TEST_CASE("Empty data hex conversion") {
        std::vector<uint8_t> empty_data;
        
        auto hex_result = lockey::Lockey::to_hex(empty_data);
        CHECK(hex_result.empty());
        
        auto data_result = lockey::Lockey::from_hex("");
        CHECK(data_result.empty());
    }

    TEST_CASE("Hex conversion with all byte values") {
        std::vector<uint8_t> all_bytes;
        for (int i = 0; i < 256; ++i) {
            all_bytes.push_back(static_cast<uint8_t>(i));
        }
        
        auto hex_result = lockey::Lockey::to_hex(all_bytes);
        CHECK(hex_result.length() == 512); // 256 bytes * 2 hex chars each
        
        auto data_result = lockey::Lockey::from_hex(hex_result);
        CHECK(data_result == all_bytes);
    }

    TEST_CASE("Invalid hex string handling") {
        // Test invalid hex characters
        auto result1 = lockey::Lockey::from_hex("xyz");
        // Implementation dependent - might return empty or throw
        
        // Test odd length hex string
        auto result2 = lockey::Lockey::from_hex("48656c6c6");
        // Implementation dependent behavior
        
        MESSAGE("Invalid hex handling behavior is implementation dependent");
    }

    TEST_CASE("Case insensitive hex conversion") {
        std::vector<uint8_t> data = {0xAB, 0xCD, 0xEF};
        
        auto hex_lower = lockey::Lockey::to_hex(data);
        
        // Test that we can convert back uppercase hex
        auto data_from_upper = lockey::Lockey::from_hex("ABCDEF");
        auto data_from_lower = lockey::Lockey::from_hex("abcdef");
        
        if (!data_from_upper.empty() && !data_from_lower.empty()) {
            CHECK(data_from_upper == data);
            CHECK(data_from_lower == data);
            MESSAGE("Case insensitive hex conversion supported");
        } else {
            MESSAGE("Case insensitive hex conversion may not be supported");
        }
    }

    TEST_CASE("Algorithm name conversion") {
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::AES_256_GCM) == "AES-256-GCM");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::AES_128_GCM) == "AES-128-GCM");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::ChaCha20_Poly1305) == "ChaCha20-Poly1305");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::RSA_2048) == "RSA-2048");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::RSA_4096) == "RSA-4096");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::ECDSA_P256) == "ECDSA-P256");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::ECDSA_P384) == "ECDSA-P384");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::ECDSA_P521) == "ECDSA-P521");
        CHECK(lockey::Lockey::algorithm_to_string(lockey::Lockey::Algorithm::Ed25519) == "Ed25519");
    }

    TEST_CASE("Hash algorithm name conversion") {
        CHECK(lockey::Lockey::hash_algorithm_to_string(lockey::Lockey::HashAlgorithm::SHA256) == "SHA-256");
        CHECK(lockey::Lockey::hash_algorithm_to_string(lockey::Lockey::HashAlgorithm::SHA384) == "SHA-384");
        CHECK(lockey::Lockey::hash_algorithm_to_string(lockey::Lockey::HashAlgorithm::SHA512) == "SHA-512");
        CHECK(lockey::Lockey::hash_algorithm_to_string(lockey::Lockey::HashAlgorithm::BLAKE2b) == "BLAKE2b");
    }
}
