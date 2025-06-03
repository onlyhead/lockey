#include "lockey/lockey.hpp"
#include <iostream>
#include <chrono>

int main() {
    try {
        std::cout << "Testing RSA key generation..." << std::endl;
        
        lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
        auto keypair = crypto.generate_keypair();
        
        std::cout << "✅ RSA key generation successful!" << std::endl;
        
        // Test hashing separately
        std::cout << "Testing hashing..." << std::endl;
        std::string test_msg = "Hello RSA!";
        std::vector<uint8_t> message(test_msg.begin(), test_msg.end());
        
        auto start = std::chrono::high_resolution_clock::now();
        auto hash_result = crypto.hash(message);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "Hashing took: " << duration.count() << "ms" << std::endl;
        std::cout << "Hash success: " << hash_result.success << std::endl;
        std::cout << "Hash size: " << hash_result.data.size() << std::endl;
        
        if (!hash_result.success) {
            std::cout << "❌ Hashing failed: " << hash_result.error_message << std::endl;
            return 1;
        }
        
        std::cout << "✅ Hashing successful!" << std::endl;
        
        // Test the RSA implementation directly
        std::cout << "Testing RSA implementation directly..." << std::endl;
        lockey::rsa::RSAImpl rsa_impl(2048);
        
        // Create a simple private key structure
        lockey::rsa::PrivateKey priv_key;
        priv_key.key_size = 2048;
        priv_key.d = keypair.private_key;
        
        // Generate simple dummy data for n
        priv_key.n.resize(256);
        for (size_t i = 0; i < 256; i++) {
            priv_key.n[i] = static_cast<uint8_t>(i % 256);
        }
        
        start = std::chrono::high_resolution_clock::now();
        try {
            auto signature = rsa_impl.sign(hash_result.data, priv_key, lockey::rsa::PaddingScheme::PKCS1_V15);
            end = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            
            std::cout << "Direct RSA signing took: " << duration.count() << "ms" << std::endl;
            std::cout << "Signature size: " << signature.size() << std::endl;
            std::cout << "✅ Direct RSA signing successful!" << std::endl;
        } catch (const std::exception& e) {
            end = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            std::cout << "Direct RSA signing took: " << duration.count() << "ms before error" << std::endl;
            std::cout << "❌ Direct RSA signing failed: " << e.what() << std::endl;
            return 1;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "❌ Exception: " << e.what() << std::endl;
        return 1;
    }
}
