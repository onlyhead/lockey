#include "lockey/lockey.hpp"
#include <iostream>
#include <cassert>

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "Comprehensive Lockey Test Suite\n";
    std::cout << "===============================\n\n";
    
    try {
        // Test 1: Multiple symmetric encryption algorithms
        std::cout << "=== Test 1: Multiple Symmetric Encryption Algorithms ===\n";
        std::string plaintext_str = "Test message for comprehensive encryption testing!";
        std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
        
        // Test AES-256-GCM
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
            
            auto key_result = crypto.generate_symmetric_key(32);
            assert(key_result.success && "Failed to generate AES key");
            
            auto encrypt_result = crypto.encrypt(plaintext, key_result.data);
            assert(encrypt_result.success && "Failed to encrypt with AES");
            
            auto decrypt_result = crypto.decrypt(encrypt_result.data, key_result.data);
            assert(decrypt_result.success && "Failed to decrypt with AES");
            
            std::string decrypted_str(decrypt_result.data.begin(), decrypt_result.data.end());
            assert(plaintext_str == decrypted_str && "AES decryption mismatch");
            
            std::cout << "✓ AES-256-GCM: PASSED\n";
        }
        
        // Test AES-128-GCM
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_128_GCM);
            
            auto key_result = crypto.generate_symmetric_key(16);
            assert(key_result.success && "Failed to generate AES-128 key");
            
            auto encrypt_result = crypto.encrypt(plaintext, key_result.data);
            assert(encrypt_result.success && "Failed to encrypt with AES-128");
            
            auto decrypt_result = crypto.decrypt(encrypt_result.data, key_result.data);
            assert(decrypt_result.success && "Failed to decrypt with AES-128");
            
            std::string decrypted_str(decrypt_result.data.begin(), decrypt_result.data.end());
            assert(plaintext_str == decrypted_str && "AES-128 decryption mismatch");
            
            std::cout << "✓ AES-128-GCM: PASSED\n";
        }
        
        // Test 2: Elliptic Curve Cryptography
        std::cout << "\n=== Test 2: Elliptic Curve Cryptography ===\n";
        
        // Test P-256
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P256);
            
            auto keypair = crypto.generate_keypair();
            assert(!keypair.public_key.empty() && "Failed to generate P-256 keypair");
            
            std::vector<uint8_t> message(plaintext.begin(), plaintext.end());
            auto sign_result = crypto.sign(message, keypair.private_key);
            assert(sign_result.success && "Failed to sign with P-256");
            
            auto verify_result = crypto.verify(message, sign_result.data, keypair.public_key);
            assert(verify_result.success && "Failed to verify P-256 signature");
            
            std::cout << "✓ ECDSA P-256: PASSED\n";
        }
        
        // Test P-384
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::ECDSA_P384);
            
            auto keypair = crypto.generate_keypair();
            assert(!keypair.public_key.empty() && "Failed to generate P-384 keypair");
            
            std::vector<uint8_t> message(plaintext.begin(), plaintext.end());
            auto sign_result = crypto.sign(message, keypair.private_key);
            assert(sign_result.success && "Failed to sign with P-384");
            
            auto verify_result = crypto.verify(message, sign_result.data, keypair.public_key);
            assert(verify_result.success && "Failed to verify P-384 signature");
            
            std::cout << "✓ ECDSA P-384: PASSED\n";
        }
        
        // Test 3: Hash Functions
        std::cout << "\n=== Test 3: Hash Functions ===\n";
        
        // Test SHA-256
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                                 lockey::Lockey::HashAlgorithm::SHA256);
            
            auto hash_result = crypto.hash(plaintext);
            assert(hash_result.success && "Failed to compute SHA-256");
            assert(hash_result.data.size() == 32 && "SHA-256 incorrect size");
            
            std::cout << "✓ SHA-256: PASSED\n";
        }
        
        // Test SHA-384
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                                 lockey::Lockey::HashAlgorithm::SHA384);
            
            auto hash_result = crypto.hash(plaintext);
            assert(hash_result.success && "Failed to compute SHA-384");
            assert(hash_result.data.size() == 48 && "SHA-384 incorrect size");
            
            std::cout << "✓ SHA-384: PASSED\n";
        }
        
        // Test SHA-512
        {
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, 
                                 lockey::Lockey::HashAlgorithm::SHA512);
            
            auto hash_result = crypto.hash(plaintext);
            assert(hash_result.success && "Failed to compute SHA-512");
            assert(hash_result.data.size() == 64 && "SHA-512 incorrect size");
            
            std::cout << "✓ SHA-512: PASSED\n";
        }
        
        // Test 4: Utility Functions
        std::cout << "\n=== Test 4: Utility Functions ===\n";
        
        {
            lockey::Lockey crypto;
            
            // Test hex conversion
            std::vector<uint8_t> test_data = {0xDE, 0xAD, 0xBE, 0xEF};
            std::string hex = crypto.to_hex(test_data);
            auto converted_back = crypto.from_hex(hex);
            
            assert(test_data == converted_back && "Hex conversion roundtrip failed");
            std::cout << "✓ Hex conversion: PASSED\n";
        }
        
        std::cout << "\n=== All Tests Completed Successfully! ===\n";
        std::cout << "✓ Symmetric encryption with multiple algorithms\n";
        std::cout << "✓ Elliptic curve cryptography (P-256, P-384)\n";
        std::cout << "✓ Hash functions (SHA-256, SHA-384, SHA-512)\n";
        std::cout << "✓ Utility functions\n";
        std::cout << "\nLockey cryptographic library is fully functional!\n";
        
    } catch (const std::exception& e) {
        std::cout << "✗ Exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "✗ Unknown exception occurred" << std::endl;
        return 1;
    }
    
    return 0;
}
