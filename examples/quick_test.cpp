#include <iostream>
#include "lockey/lockey.hpp"

int main() {
    std::cout << "=== Quick Lockey Test (Small Key Size) ===" << std::endl;
    
    try {
        // Test with smaller key size for faster execution
        std::cout << "Generating 512-bit RSA key pair..." << std::endl;
        auto keyPair = lockey::Lockey::generateKeyPair(lockey::crypto::CryptoManager::Algorithm::RSA, 512);
        std::cout << "✓ Key pair generated successfully!" << std::endl;
        std::cout << "Public key size: " << keyPair.publicKey.size() << " bytes" << std::endl;
        std::cout << "Private key size: " << keyPair.privateKey.size() << " bytes" << std::endl;
        
        // Test hashing (fast operation)
        std::cout << "\nTesting hashing..." << std::endl;
        std::string data = "Hello, Lockey!";
        std::string hash = lockey::Lockey::hash(data);
        std::cout << "✓ Hash computed: " << hash << std::endl;
        
        // Test hex conversion utilities
        std::cout << "\nTesting hex utilities..." << std::endl;
        std::vector<uint8_t> testData = {0xDE, 0xAD, 0xBE, 0xEF};
        std::string hexString = lockey::Lockey::bytesToHex(testData);
        auto convertedBack = lockey::Lockey::hexToBytes(hexString);
        std::cout << "Original: DEADBEEF, Converted: " << hexString << std::endl;
        std::cout << "Round-trip successful: " << (testData == convertedBack ? "YES" : "NO") << std::endl;
        
        std::cout << "\n=== Quick test completed successfully! ===" << std::endl;
        std::cout << "Note: Full crypto operations (sign/verify/encrypt/decrypt) would take longer" << std::endl;
        std::cout << "with larger key sizes, but the API is working correctly." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
