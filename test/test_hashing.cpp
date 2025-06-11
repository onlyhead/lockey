#include <doctest/doctest.h>
#include "lockey/lockey.hpp"

TEST_SUITE("Hash Functions") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    const std::vector<uint8_t> empty_data;

    TEST_CASE("SHA-256 hashing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        auto result = crypto.hash(test_data);
        REQUIRE(result.success);
        CHECK(result.data.size() == 32); // SHA-256 produces 32 bytes
        CHECK(result.error_message.empty());
        
        // Test consistency - same input should produce same hash
        auto result2 = crypto.hash(test_data);
        REQUIRE(result2.success);
        CHECK(result.data == result2.data);
    }

    TEST_CASE("SHA-384 hashing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA384);
        
        auto result = crypto.hash(test_data);
        REQUIRE(result.success);
        CHECK(result.data.size() == 48); // SHA-384 produces 48 bytes
        CHECK(result.error_message.empty());
    }

    TEST_CASE("SHA-512 hashing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA512);
        
        auto result = crypto.hash(test_data);
        REQUIRE(result.success);
        CHECK(result.data.size() == 64); // SHA-512 produces 64 bytes
        CHECK(result.error_message.empty());
    }

    TEST_CASE("BLAKE2b hashing (should fail - not implemented)") {
        // This should throw during construction
        CHECK_THROWS_AS(lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                                            lockey::Lockey::HashAlgorithm::BLAKE2b), 
                       std::runtime_error);
    }

    TEST_CASE("Empty data hashing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        auto result = crypto.hash(empty_data);
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
        
        // SHA-256 of empty string should be known value
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        std::vector<uint8_t> expected_empty_sha256 = {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        };
        CHECK(result.data == expected_empty_sha256);
    }

    TEST_CASE("Large data hashing") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        std::vector<uint8_t> large_data(1000000, 0x41); // 1MB of 'A'
        
        auto result = crypto.hash(large_data);
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("Different algorithms produce different hashes") {
        std::vector<uint8_t> data = {0x74, 0x65, 0x73, 0x74}; // "test"
        
        lockey::Lockey crypto256(lockey::Lockey::Algorithm::AES_256_GCM, 
                                lockey::Lockey::HashAlgorithm::SHA256);
        lockey::Lockey crypto384(lockey::Lockey::Algorithm::AES_256_GCM, 
                                lockey::Lockey::HashAlgorithm::SHA384);
        lockey::Lockey crypto512(lockey::Lockey::Algorithm::AES_256_GCM, 
                                lockey::Lockey::HashAlgorithm::SHA512);
        
        auto hash256 = crypto256.hash(data);
        auto hash384 = crypto384.hash(data);
        auto hash512 = crypto512.hash(data);
        
        REQUIRE(hash256.success);
        REQUIRE(hash384.success);
        REQUIRE(hash512.success);
        
        CHECK(hash256.data != hash384.data);
        CHECK(hash256.data != hash512.data);
        CHECK(hash384.data != hash512.data);
        
        CHECK(hash256.data.size() == 32);
        CHECK(hash384.data.size() == 48);
        CHECK(hash512.data.size() == 64);
    }
}
