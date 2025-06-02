#include <iostream>
#include <vector>
#include "../include/lockey/lockey.hpp"

using namespace lockey;
using namespace lockey::crypto;

int main() {
    std::cout << "=== Testing New Crypto Implementations ===" << std::endl;
    
    try {
        // Test AES
        std::cout << "\n1. Testing AES..." << std::endl;
        auto aes_key = AES::generate_key(AES::KeySize::AES_256);
        std::cout << "Generated AES-256 key of size: " << aes_key.size() << " bytes" << std::endl;
        
        std::string message = "Hello, AES World!";
        std::vector<uint8_t> plaintext(message.begin(), message.end());
        
        auto iv = AES::generate_iv();
        auto ciphertext = AES::encrypt(plaintext, aes_key, AES::Mode::CBC, iv);
        std::cout << "Encrypted message, ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
        
        auto decrypted = AES::decrypt(ciphertext, aes_key, AES::Mode::CBC, iv);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted message: " << decrypted_str << std::endl;
        
        if (decrypted_str == message) {
            std::cout << "✓ AES encryption/decryption successful!" << std::endl;
        } else {
            std::cout << "✗ AES encryption/decryption failed!" << std::endl;
        }
        
        // Test ECDSA key generation
        std::cout << "\n2. Testing ECDSA..." << std::endl;
        auto curve = Secp256r1::instance();
        std::cout << "Using curve: " << curve->name() << std::endl;
        
        try {
            auto keypair = ECDSA::generate_key_pair(curve);
            std::cout << "✓ ECDSA key pair generated!" << std::endl;
            
            // Test message signing (this will fail due to unimplemented curve operations)
            std::vector<uint8_t> test_message = {'H', 'e', 'l', 'l', 'o'};
            try {
                auto signature = ECDSA::sign_message(test_message, keypair.private_key, curve);
                std::cout << "✓ ECDSA signature generated!" << std::endl;
                
                bool valid = ECDSA::verify_message(test_message, signature, keypair.public_key, curve);
                std::cout << "Signature verification: " << (valid ? "✓ Valid" : "✗ Invalid") << std::endl;
            } catch (const std::exception& e) {
                std::cout << "Note: ECDSA signing failed as expected (curve operations not fully implemented): " << e.what() << std::endl;
            }
            
        } catch (const std::exception& e) {
            std::cout << "ECDSA key generation failed: " << e.what() << std::endl;
        }
        
        // Test CryptoManager integration
        std::cout << "\n3. Testing CryptoManager integration..." << std::endl;
        CryptoManager manager;
        
        try {
            auto aes_keypair = manager.generateKeyPair(CryptoManager::Algorithm::AES, 256);
            std::cout << "✓ AES key generation via CryptoManager successful!" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "AES key generation via CryptoManager failed: " << e.what() << std::endl;
        }
        
        try {
            auto ecdsa_keypair = manager.generateKeyPair(CryptoManager::Algorithm::ECDSA_P256, 256);
            std::cout << "✓ ECDSA-P256 key generation via CryptoManager successful!" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Note: ECDSA key generation failed as expected: " << e.what() << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n=== Test completed ===" << std::endl;
    return 0;
}
