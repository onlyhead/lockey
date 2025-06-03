#include "include/lockey/rsa/rsa_crypto.hpp"
#include <iostream>
#include <vector>

int main() {
    try {
        std::cout << "=== Simple RSA Test ===" << std::endl;
        
        // Create RSA implementation with 2048-bit keys
        lockey::rsa::RSAImpl rsa(2048);
        
        // Generate a key pair
        std::cout << "Generating RSA keypair..." << std::endl;
        auto keypair = rsa.generate_keypair();
        
        // Extract public and private keys
        auto public_key = rsa.extract_public_key(keypair);
        auto private_key = rsa.extract_private_key(keypair);
        
        // Validate keys
        std::cout << "Validating keys..." << std::endl;
        if (!rsa.validate_public_key(public_key)) {
            std::cout << "✗ Public key validation failed" << std::endl;
            return 1;
        }
        if (!rsa.validate_private_key(private_key)) {
            std::cout << "✗ Private key validation failed" << std::endl;
            return 1;
        }
        if (!rsa.validate_keypair(keypair)) {
            std::cout << "✗ Keypair validation failed" << std::endl;
            return 1;
        }
        
        std::cout << "✓ RSA key generation and validation: PASSED" << std::endl;
        
        // Test data
        std::vector<uint8_t> test_data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
        
        // Test encryption/decryption with PKCS1_V15
        std::cout << "Testing PKCS#1 v1.5 encryption..." << std::endl;
        auto encrypted = rsa.encrypt(test_data, public_key, lockey::rsa::PaddingScheme::PKCS1_V15);
        auto decrypted = rsa.decrypt(encrypted, private_key, lockey::rsa::PaddingScheme::PKCS1_V15);
        
        if (decrypted == test_data) {
            std::cout << "✓ PKCS#1 v1.5 encryption/decryption: PASSED" << std::endl;
        } else {
            std::cout << "✗ PKCS#1 v1.5 encryption/decryption: FAILED" << std::endl;
            return 1;
        }
        
        // Test signing/verification with PKCS1_V15
        std::cout << "Testing PKCS#1 v1.5 signing..." << std::endl;
        auto signature = rsa.sign(test_data, private_key, lockey::rsa::PaddingScheme::PKCS1_V15);
        bool verified = rsa.verify(test_data, signature, public_key, lockey::rsa::PaddingScheme::PKCS1_V15);
        
        if (verified) {
            std::cout << "✓ PKCS#1 v1.5 signing/verification: PASSED" << std::endl;
        } else {
            std::cout << "✗ PKCS#1 v1.5 signing/verification: FAILED" << std::endl;
            return 1;
        }
        
        std::cout << "\n=== All RSA tests passed! ===" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cout << "✗ Exception: " << e.what() << std::endl;
        return 1;
    }
}
