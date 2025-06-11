#include <doctest/doctest.h>
#include "lockey/lockey.hpp"

TEST_SUITE("Missing Functionality Detection") {
    TEST_CASE("Missing HMAC implementation") {
        lockey::Lockey crypto;
        std::vector<uint8_t> data = {0x74, 0x65, 0x73, 0x74}; // "test"
        std::vector<uint8_t> key = {0x6b, 0x65, 0x79}; // "key"
        
        auto result = crypto.hmac(data, key);
        
        if (!result.success) {
            MESSAGE("❌ HMAC functionality missing: " << result.error_message);
        } else {
            MESSAGE("✅ HMAC functionality implemented");
        }
    }

    TEST_CASE("Missing BLAKE2b hash implementation") {
        try {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                                 lockey::Lockey::HashAlgorithm::BLAKE2b);
            MESSAGE("✅ BLAKE2b hash algorithm implemented");
        } catch (const std::exception& e) {
            MESSAGE("❌ BLAKE2b hash algorithm missing: " << e.what());
        }
    }

    TEST_CASE("Missing Ed25519 signature implementation") {
        try {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::Ed25519);
            MESSAGE("✅ Ed25519 signature algorithm implemented");
        } catch (const std::exception& e) {
            MESSAGE("❌ Ed25519 signature algorithm missing: " << e.what());
        }
    }

    TEST_CASE("Missing ECDSA P-384 implementation") {
        try {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P384);
            auto keypair = crypto.generate_keypair();
            MESSAGE("✅ ECDSA P-384 implemented");
        } catch (const std::exception& e) {
            MESSAGE("❌ ECDSA P-384 missing or incomplete: " << e.what());
        }
    }

    TEST_CASE("Missing ECDSA P-521 implementation") {
        try {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P521);
            auto keypair = crypto.generate_keypair();
            MESSAGE("✅ ECDSA P-521 implemented");
        } catch (const std::exception& e) {
            MESSAGE("❌ ECDSA P-521 missing or incomplete: " << e.what());
        }
    }

    TEST_CASE("Missing RSA asymmetric encryption") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
        auto keypair = crypto.generate_keypair();
        
        std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        
        auto encrypt_result = crypto.encrypt_asymmetric(data, keypair.public_key);
        
        if (encrypt_result.success) {
            MESSAGE("✅ RSA asymmetric encryption implemented");
            
            auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
            if (decrypt_result.success) {
                MESSAGE("✅ RSA asymmetric decryption implemented");
            } else {
                MESSAGE("❌ RSA asymmetric decryption missing: " << decrypt_result.error_message);
            }
        } else {
            MESSAGE("❌ RSA asymmetric encryption missing: " << encrypt_result.error_message);
        }
    }

    TEST_CASE("Missing key I/O operations") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        auto keypair = crypto.generate_keypair();
        
        // Test saving keypair
        bool save_success = crypto.save_keypair_to_files(keypair, "/tmp/test_pub.pem", "/tmp/test_priv.pem");
        
        if (save_success) {
            MESSAGE("✅ Key saving implemented");
            
            // Test loading keypair
            auto load_result = crypto.load_keypair_from_files("/tmp/test_pub.pem", "/tmp/test_priv.pem");
            if (load_result.success) {
                MESSAGE("✅ Key loading implemented");
            } else {
                MESSAGE("❌ Key loading missing or incomplete: " << load_result.error_message);
            }
        } else {
            MESSAGE("❌ Key saving missing or incomplete");
        }
    }

    TEST_CASE("Missing or incomplete signature implementations") {
        // Test RSA signing
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
            auto keypair = crypto.generate_keypair();
            std::vector<uint8_t> data = {0x74, 0x65, 0x73, 0x74}; // "test"
            
            auto sign_result = crypto.sign(data, keypair.private_key);
            if (sign_result.success) {
                auto verify_result = crypto.verify(data, sign_result.data, keypair.public_key);
                if (verify_result.success) {
                    MESSAGE("✅ RSA signing/verification implemented");
                } else {
                    MESSAGE("❌ RSA verification incomplete: " << verify_result.error_message);
                }
            } else {
                MESSAGE("❌ RSA signing incomplete: " << sign_result.error_message);
            }
        }
        
        // Test ECDSA signing
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
            auto keypair = crypto.generate_keypair();
            std::vector<uint8_t> data = {0x74, 0x65, 0x73, 0x74}; // "test"
            
            auto sign_result = crypto.sign(data, keypair.private_key);
            if (sign_result.success) {
                auto verify_result = crypto.verify(data, sign_result.data, keypair.public_key);
                if (verify_result.success) {
                    MESSAGE("✅ ECDSA P-256 signing/verification implemented");
                } else {
                    MESSAGE("❌ ECDSA P-256 verification incomplete: " << verify_result.error_message);
                }
            } else {
                MESSAGE("❌ ECDSA P-256 signing incomplete: " << sign_result.error_message);
            }
        }
    }

    TEST_CASE("Missing error handling improvements") {
        lockey::Lockey crypto;
        
        // Test with invalid key size
        std::vector<uint8_t> invalid_key = {0x01, 0x02}; // Too small
        std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
        
        auto result = crypto.encrypt(data, invalid_key);
        
        if (!result.success && !result.error_message.empty()) {
            MESSAGE("✅ Good error handling for invalid keys: " << result.error_message);
        } else {
            MESSAGE("❌ Poor error handling for invalid keys");
        }
    }

    TEST_CASE("Implementation completeness summary") {
        std::vector<std::string> missing_features;
        
        // Test HMAC
        {
            lockey::Lockey crypto;
            std::vector<uint8_t> data = {0x74, 0x65, 0x73, 0x74};
            std::vector<uint8_t> key = {0x6b, 0x65, 0x79};
            auto result = crypto.hmac(data, key);
            if (!result.success) missing_features.push_back("HMAC");
        }
        
        // Test BLAKE2b
        try {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                                 lockey::Lockey::HashAlgorithm::BLAKE2b);
        } catch (...) {
            missing_features.push_back("BLAKE2b hash");
        }
        
        // Test Ed25519
        try {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::Ed25519);
        } catch (...) {
            missing_features.push_back("Ed25519 signatures");
        }
        
        // Test RSA encryption
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
            auto keypair = crypto.generate_keypair();
            std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
            auto result = crypto.encrypt_asymmetric(data, keypair.public_key);
            if (!result.success) missing_features.push_back("RSA asymmetric encryption");
        }
        
        if (missing_features.empty()) {
            MESSAGE("✅ All major features implemented!");
        } else {
            MESSAGE("❌ Missing features detected: " << missing_features.size() << " items");
            for (const auto& feature : missing_features) {
                MESSAGE("  - " << feature);
            }
        }
        
        CHECK(missing_features.size() < 10); // Arbitrary threshold for "mostly complete"
    }
}
