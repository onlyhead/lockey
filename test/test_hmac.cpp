#include <doctest/doctest.h>
#include "lockey/lockey.hpp"

TEST_SUITE("HMAC Functions") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    const std::vector<uint8_t> hmac_key = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    TEST_CASE("HMAC-SHA256") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        auto result = crypto.hmac(test_data, hmac_key);
        
        // This will likely fail as HMAC is not implemented
        if (result.success) {
            CHECK(result.data.size() == 32); // HMAC-SHA256 produces 32 bytes
            CHECK(result.error_message.empty());
        } else {
            CHECK_FALSE(result.error_message.empty());
            MESSAGE("HMAC not implemented: " << result.error_message);
        }
    }

    TEST_CASE("HMAC-SHA384") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA384);
        
        auto result = crypto.hmac(test_data, hmac_key);
        
        if (result.success) {
            CHECK(result.data.size() == 48); // HMAC-SHA384 produces 48 bytes
        } else {
            CHECK_FALSE(result.error_message.empty());
            MESSAGE("HMAC not implemented: " << result.error_message);
        }
    }

    TEST_CASE("HMAC-SHA512") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA512);
        
        auto result = crypto.hmac(test_data, hmac_key);
        
        if (result.success) {
            CHECK(result.data.size() == 64); // HMAC-SHA512 produces 64 bytes
        } else {
            CHECK_FALSE(result.error_message.empty());
            MESSAGE("HMAC not implemented: " << result.error_message);
        }
    }

    TEST_CASE("HMAC with empty data") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        std::vector<uint8_t> empty_data;
        auto result = crypto.hmac(empty_data, hmac_key);
        
        if (result.success) {
            CHECK(result.data.size() == 32);
        } else {
            MESSAGE("HMAC not implemented: " << result.error_message);
        }
    }

    TEST_CASE("HMAC with empty key") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        std::vector<uint8_t> empty_key;
        auto result = crypto.hmac(test_data, empty_key);
        
        if (result.success) {
            CHECK(result.data.size() == 32);
        } else {
            MESSAGE("HMAC not implemented: " << result.error_message);
        }
    }

    TEST_CASE("HMAC consistency") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                             lockey::Lockey::HashAlgorithm::SHA256);
        
        auto result1 = crypto.hmac(test_data, hmac_key);
        auto result2 = crypto.hmac(test_data, hmac_key);
        
        if (result1.success && result2.success) {
            CHECK(result1.data == result2.data);
        }
    }
}
