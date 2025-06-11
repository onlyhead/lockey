#include "lockey/lockey.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Symmetric Encryption") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                                            0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    const std::vector<uint8_t> aes_256_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                              0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                              0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    const std::vector<uint8_t> aes_128_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    TEST_CASE("AES-256-GCM encryption/decryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, aes_256_key);
        REQUIRE(encrypt_result.success);
        CHECK(encrypt_result.data.size() > test_data.size()); // Should be larger due to IV + tag
        CHECK(encrypt_result.error_message.empty());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, aes_256_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
        CHECK(decrypt_result.error_message.empty());
    }

    TEST_CASE("AES-128-GCM encryption/decryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_128_GCM);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, aes_128_key);
        REQUIRE(encrypt_result.success);
        CHECK(encrypt_result.data.size() > test_data.size());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, aes_128_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
    }

    TEST_CASE("ChaCha20-Poly1305 encryption/decryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ChaCha20_Poly1305);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, aes_256_key); // ChaCha20 also uses 32-byte key
        REQUIRE(encrypt_result.success);
        CHECK(encrypt_result.data.size() > test_data.size());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, aes_256_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
    }

    TEST_CASE("Encryption with associated data (AEAD)") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        std::vector<uint8_t> associated_data = {0x41, 0x44, 0x44, 0x44}; // "ADDD"

        // Test encryption with AAD
        auto encrypt_result = crypto.encrypt(test_data, aes_256_key, associated_data);
        REQUIRE(encrypt_result.success);

        // Test decryption with correct AAD
        auto decrypt_result = crypto.decrypt(encrypt_result.data, aes_256_key, associated_data);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);

        // Test decryption with wrong AAD (should fail)
        std::vector<uint8_t> wrong_aad = {0x42, 0x41, 0x44, 0x44}; // "BADD"
        auto decrypt_wrong_result = crypto.decrypt(encrypt_result.data, aes_256_key, wrong_aad);
        CHECK_FALSE(decrypt_wrong_result.success);
        CHECK_FALSE(decrypt_wrong_result.error_message.empty());
    }

    TEST_CASE("Invalid key sizes") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        std::vector<uint8_t> wrong_key = {0x01, 0x02, 0x03}; // Too short

        auto result = crypto.encrypt(test_data, wrong_key);
        CHECK_FALSE(result.success);
        CHECK_FALSE(result.error_message.empty());
    }

    TEST_CASE("Empty data encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        std::vector<uint8_t> empty_data;

        auto encrypt_result = crypto.encrypt(empty_data, aes_256_key);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, aes_256_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data.empty());
    }

    TEST_CASE("Large data encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        std::vector<uint8_t> large_data(10000, 0x42); // 10KB of 'B'

        auto encrypt_result = crypto.encrypt(large_data, aes_256_key);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, aes_256_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == large_data);
    }

    TEST_CASE("Wrong algorithm for symmetric encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        auto result = crypto.encrypt(test_data, aes_256_key);
        CHECK_FALSE(result.success);
        CHECK(result.error_message.find("not suitable for symmetric encryption") != std::string::npos);
    }
}
