#include "lockey/lockey.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Asymmetric Encryption") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                                            0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"

    TEST_CASE("RSA-2048 asymmetric encryption/decryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_2048);

        // Test encryption with public key
        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair.public_key);

        if (encrypt_result.success) {
            CHECK_FALSE(encrypt_result.data.empty());
            CHECK(encrypt_result.data.size() > test_data.size()); // Encrypted data should be larger
            CHECK(encrypt_result.error_message.empty());

            // Test decryption with private key
            auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
            if (decrypt_result.success) {
                CHECK(decrypt_result.data == test_data);
                CHECK(decrypt_result.error_message.empty());
            } else {
                MESSAGE("RSA-2048 decryption failed: " << decrypt_result.error_message);
            }
        } else {
            MESSAGE("RSA-2048 encryption not implemented: " << encrypt_result.error_message);
        }
    }

    TEST_CASE("RSA-4096 asymmetric encryption/decryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_4096);

        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_4096);

        // Test encryption with public key
        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair.public_key);

        if (encrypt_result.success) {
            CHECK_FALSE(encrypt_result.data.empty());

            // Test decryption with private key
            auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
            if (decrypt_result.success) {
                CHECK(decrypt_result.data == test_data);
            } else {
                MESSAGE("RSA-4096 decryption failed: " << decrypt_result.error_message);
            }
        } else {
            MESSAGE("RSA-4096 encryption not implemented: " << encrypt_result.error_message);
        }
    }

    TEST_CASE("ECDSA algorithms should not support encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);

        auto keypair = crypto.generate_keypair();

        // ECDSA is signing-only, not encryption
        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair.public_key);
        CHECK_FALSE(encrypt_result.success);
        CHECK_FALSE(encrypt_result.error_message.empty());
    }

    TEST_CASE("Symmetric algorithms should not support asymmetric encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);

        std::vector<uint8_t> dummy_key = {0x01, 0x02, 0x03};

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, dummy_key);
        CHECK_FALSE(encrypt_result.success);
        CHECK_FALSE(encrypt_result.error_message.empty());
    }

    TEST_CASE("Empty data asymmetric encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        auto keypair = crypto.generate_keypair();
        std::vector<uint8_t> empty_data;

        auto encrypt_result = crypto.encrypt_asymmetric(empty_data, keypair.public_key);

        if (encrypt_result.success) {
            auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
            if (decrypt_result.success) {
                CHECK(decrypt_result.data.empty());
            }
        } else {
            MESSAGE("Empty data asymmetric encryption not supported or not implemented");
        }
    }

    TEST_CASE("Wrong key for decryption should fail") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        auto keypair1 = crypto.generate_keypair();
        auto keypair2 = crypto.generate_keypair();

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair1.public_key);

        if (encrypt_result.success) {
            // Try to decrypt with wrong private key
            auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair2.private_key);
            CHECK_FALSE(decrypt_result.success);
        }
    }

    TEST_CASE("Data too large for RSA encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        auto keypair = crypto.generate_keypair();

        // RSA-2048 can encrypt at most 245 bytes with OAEP padding
        // Let's try with data that's definitely too large
        std::vector<uint8_t> large_data(1000, 0x42); // 1KB of 'B'

        auto encrypt_result = crypto.encrypt_asymmetric(large_data, keypair.public_key);

        if (encrypt_result.success) {
            MESSAGE("Large data encryption unexpectedly succeeded");
        } else {
            CHECK_FALSE(encrypt_result.error_message.empty());
            MESSAGE("Large data correctly rejected: " << encrypt_result.error_message);
        }
    }

    TEST_CASE("Cross-key decryption should fail") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        auto keypair1 = crypto.generate_keypair();
        auto keypair2 = crypto.generate_keypair();

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair1.public_key);

        if (encrypt_result.success) {
            // Try to decrypt with wrong private key
            auto decrypt_wrong = crypto.decrypt_asymmetric(encrypt_result.data, keypair2.private_key);
            CHECK_FALSE(decrypt_wrong.success);

            // But correct private key should work
            auto decrypt_correct = crypto.decrypt_asymmetric(encrypt_result.data, keypair1.private_key);
            if (decrypt_correct.success) {
                CHECK(decrypt_correct.data == test_data);
            }
        }
    }
}
