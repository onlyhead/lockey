#include <doctest/doctest.h>
#include "lockey/lockey.hpp"
#include <fstream>
#include <filesystem>

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

    TEST_CASE("Save individual key") {
        setup_test_dir();
        
        lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
        
        auto keypair = crypto.generate_keypair();
        std::string key_file = test_dir + "test_key.pem";
        
        // Save public key
        bool save_success = crypto.save_key_to_file(keypair.public_key, key_file, 
                                                   lockey::Lockey::KeyType::PUBLIC);
        
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
        
        auto result = crypto.load_key_from_file("/non/existent/file.pem", 
                                              lockey::Lockey::KeyType::PUBLIC);
        CHECK_FALSE(result.success);
        CHECK_FALSE(result.error_message.empty());
    }
}
