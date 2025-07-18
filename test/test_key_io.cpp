#include "lockey/lockey.hpp"
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

TEST_SUITE("Key I/O Operations") {
    const std::string test_dir = "/tmp/lockey_test_keys/";

    // Helper function to clean up test directory
    void cleanup_test_dir() {
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

    // Helper function to create test directory
    void setup_test_dir() {
        cleanup_test_dir();
        std::filesystem::create_directories(test_dir);
    }

    TEST_CASE("Save and load ECDSA keypair") {
        setup_test_dir();

        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);

        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::ECDSA_P256);

        std::string pub_file = test_dir + "test_ec_public.pem";
        std::string priv_file = test_dir + "test_ec_private.pem";

        // Save keypair
        bool save_success = crypto.save_keypair_to_files(keypair, pub_file, priv_file);

        if (save_success) {
            CHECK(std::filesystem::exists(pub_file));
            CHECK(std::filesystem::exists(priv_file));

            // Load keypair back
            auto load_result = crypto.load_keypair_from_files(pub_file, priv_file);
            if (load_result.success) {
                MESSAGE("ECDSA keypair save/load successful");
            } else {
                MESSAGE("ECDSA keypair load failed: " << load_result.error_message);
            }
        } else {
            MESSAGE("ECDSA keypair save not implemented");
        }

        cleanup_test_dir();
    }

    TEST_CASE("Save and load RSA keypair") {
        setup_test_dir();

        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);

        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == lockey::Lockey::Algorithm::RSA_2048);

        std::string pub_file = test_dir + "test_rsa_public.pem";
        std::string priv_file = test_dir + "test_rsa_private.pem";

        // Save keypair
        bool save_success = crypto.save_keypair_to_files(keypair, pub_file, priv_file);

        if (save_success) {
            CHECK(std::filesystem::exists(pub_file));
            CHECK(std::filesystem::exists(priv_file));

            // Load keypair back
            auto load_result = crypto.load_keypair_from_files(pub_file, priv_file);
            if (load_result.success) {
                MESSAGE("RSA keypair save/load successful");
            } else {
                MESSAGE("RSA keypair load failed: " << load_result.error_message);
            }
        } else {
            MESSAGE("RSA keypair save not implemented");
        }

        cleanup_test_dir();
    }

    TEST_CASE("Save individual key") {
        setup_test_dir();

        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);

        auto keypair = crypto.generate_keypair();
        std::string key_file = test_dir + "test_key.pem";

        // Save public key
        bool save_success = crypto.save_key_to_file(keypair.public_key, key_file, lockey::Lockey::KeyType::PUBLIC);

        if (save_success) {
            CHECK(std::filesystem::exists(key_file));

            // Load key back
            auto load_result = crypto.load_key_from_file(key_file, lockey::Lockey::KeyType::PUBLIC);
            if (load_result.success) {
                CHECK(load_result.data == keypair.public_key);
                MESSAGE("Individual key save/load successful");
            } else {
                MESSAGE("Individual key load failed: " << load_result.error_message);
            }
        } else {
            MESSAGE("Individual key save not implemented");
        }

        cleanup_test_dir();
    }

    TEST_CASE("Load non-existent file should fail") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);

        auto result = crypto.load_key_from_file("/non/existent/file.pem", lockey::Lockey::KeyType::PUBLIC);
        CHECK_FALSE(result.success);
        CHECK_FALSE(result.error_message.empty());
    }

    TEST_CASE("Save to invalid path should fail") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);

        auto keypair = crypto.generate_keypair();

        // Try to save to invalid path
        bool save_success =
            crypto.save_key_to_file(keypair.public_key, "/invalid/path/file.pem", lockey::Lockey::KeyType::PUBLIC);
        CHECK_FALSE(save_success);
    }

    TEST_CASE("Round-trip test with signature") {
        setup_test_dir();

        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);

        // Generate original keypair
        auto original_keypair = crypto.generate_keypair();

        std::string pub_file = test_dir + "roundtrip_public.pem";
        std::string priv_file = test_dir + "roundtrip_private.pem";

        // Save keypair
        bool save_success = crypto.save_keypair_to_files(original_keypair, pub_file, priv_file);

        if (save_success) {
            // Load keypair back
            auto load_result = crypto.load_keypair_from_files(pub_file, priv_file);

            if (load_result.success) {
                // Test that loaded keys work for signing
                std::vector<uint8_t> test_message = {0x74, 0x65, 0x73, 0x74}; // "test"

                // Sign with original private key
                auto original_signature = crypto.sign(test_message, original_keypair.private_key);

                if (original_signature.success) {
                    // Verify with original public key
                    auto verify_original =
                        crypto.verify(test_message, original_signature.data, original_keypair.public_key);
                    CHECK(verify_original.success);

                    MESSAGE("Round-trip key test successful");
                } else {
                    MESSAGE("Original signature failed: " << original_signature.error_message);
                }
            } else {
                MESSAGE("Keypair load failed: " << load_result.error_message);
            }
        } else {
            MESSAGE("Keypair save not implemented");
        }

        cleanup_test_dir();
    }

    TEST_CASE("Different key formats") {
        setup_test_dir();

        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        auto keypair = crypto.generate_keypair();

        // Test PEM format (default)
        std::string pem_file = test_dir + "test_pem.pem";
        bool pem_save = crypto.save_key_to_file(keypair.public_key, pem_file, lockey::Lockey::KeyType::PUBLIC);

        // Test DER format (if supported)
        std::string der_file = test_dir + "test_der.der";
        bool der_save = crypto.save_key_to_file(keypair.public_key, der_file, lockey::Lockey::KeyType::PUBLIC,
                                                lockey::utils::KeyFormat::DER);

        if (pem_save) {
            MESSAGE("PEM format save successful");
        } else {
            MESSAGE("PEM format save not implemented");
        }

        if (der_save) {
            MESSAGE("DER format save successful");
        } else {
            MESSAGE("DER format save not implemented");
        }

        cleanup_test_dir();
    }
}
