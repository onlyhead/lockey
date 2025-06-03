#include "lockey/lockey.hpp"
#include <iostream>
#include <chrono>

int main() {
    try {
        std::cout << "Testing RSA key generation..." << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
        std::cout << "Created Lockey instance" << std::endl;
        
        auto keypair = crypto.generate_keypair();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "Key generation took: " << duration.count() << "ms" << std::endl;
        std::cout << "Public key size: " << keypair.public_key.size() << std::endl;
        std::cout << "Private key size: " << keypair.private_key.size() << std::endl;
        
        if (keypair.public_key.empty() || keypair.private_key.empty()) {
            std::cout << "❌ Key generation failed - empty keys" << std::endl;
            return 1;
        }
        
        std::cout << "✅ RSA key generation successful!" << std::endl;
        
        // Test signing
        std::cout << "Testing RSA signing..." << std::endl;
        std::string test_msg = "Hello RSA!";
        std::vector<uint8_t> message(test_msg.begin(), test_msg.end());
        
        start = std::chrono::high_resolution_clock::now();
        auto sign_result = crypto.sign(message, keypair.private_key);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "Signing took: " << duration.count() << "ms" << std::endl;
        std::cout << "Signature size: " << sign_result.data.size() << std::endl;
        std::cout << "Signature success: " << sign_result.success << std::endl;
        
        if (!sign_result.success) {
            std::cout << "❌ RSA signing failed" << std::endl;
            return 1;
        }
        
        std::cout << "✅ RSA signing successful!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "❌ Exception: " << e.what() << std::endl;
        return 1;
    }
}
