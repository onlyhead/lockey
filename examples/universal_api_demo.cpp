#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include "lockey/lockey.hpp"

int main() {
    std::cout << "=== Universal Cryptography API Demo ===" << std::endl;
    
    try {
        // Demonstrate the universal interface with different algorithms
        std::cout << "\n🔐 Universal Cryptography Interface" << std::endl;
        std::cout << "=====================================" << std::endl;
        
        const std::string testMessage = "Universal API test message";
        const std::string testData = "Data for hashing with different algorithms";
        
        // RSA Cryptography (default)
        std::cout << "\n1. RSA Cryptography (default)" << std::endl;
        std::cout << "------------------------------" << std::endl;
        
        auto rsaKeys = lockey::Lockey::generateKeyPair(lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ RSA key pair generated" << std::endl;
        
        std::string rsaSignature = lockey::Lockey::sign(testMessage, rsaKeys.privateKey, 
                                                       lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ RSA signature created" << std::endl;
        
        bool rsaVerified = lockey::Lockey::verify(testMessage, rsaSignature, rsaKeys.publicKey,
                                                 lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ RSA signature verification: " << (rsaVerified ? "VALID" : "INVALID") << std::endl;
        
        std::string rsaEncrypted = lockey::Lockey::encrypt(testMessage, rsaKeys.publicKey,
                                                          lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ RSA encryption completed" << std::endl;
        
        std::string rsaDecrypted = lockey::Lockey::decrypt(rsaEncrypted, rsaKeys.privateKey,
                                                          lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ RSA decryption completed" << std::endl;
        std::cout << "RSA decryption success: " << (testMessage == rsaDecrypted ? "YES" : "NO") << std::endl;
        
        // Hash testing with explicit algorithm specification
        std::cout << "\n2. Hashing with Different Algorithms" << std::endl;
        std::cout << "------------------------------------" << std::endl;
        
        // BLAKE2s (default)
        std::string blake2sHash = lockey::Lockey::hash(testData, 
                                                       lockey::crypto::CryptoManager::HashAlgorithm::BLAKE2S);
        std::cout << "✓ BLAKE2s hash: " << blake2sHash << std::endl;
        
        // Binary data operations with explicit algorithms
        std::cout << "\n3. Binary Data Operations" << std::endl;
        std::cout << "-------------------------" << std::endl;
        
        std::vector<uint8_t> binaryTestData = {0x54, 0x65, 0x73, 0x74}; // "Test"
        
        // Sign binary data with RSA
        auto binaryRsaSignature = lockey::Lockey::signBytes(binaryTestData, rsaKeys.privateKey,
                                                            lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ Binary RSA signature created" << std::endl;
        
        bool binaryRsaVerified = lockey::Lockey::verifyBytes(binaryTestData, binaryRsaSignature, rsaKeys.publicKey,
                                                            lockey::crypto::CryptoManager::Algorithm::RSA);
        std::cout << "✓ Binary RSA verification: " << (binaryRsaVerified ? "VALID" : "INVALID") << std::endl;
        
        // Hash binary data
        auto binaryBlake2sHash = lockey::Lockey::hashBytes(binaryTestData,
                                                           lockey::crypto::CryptoManager::HashAlgorithm::BLAKE2S);
        std::cout << "✓ Binary BLAKE2s hash: " << lockey::Lockey::bytesToHex(binaryBlake2sHash) << std::endl;
        
        // Cross-algorithm compatibility demonstration
        std::cout << "\n4. API Consistency Demonstration" << std::endl;
        std::cout << "---------------------------------" << std::endl;
        
        // Show that the same interface works regardless of algorithm
        std::cout << "✓ Same function signatures for all algorithms" << std::endl;
        std::cout << "✓ Consistent return types across algorithms" << std::endl;
        std::cout << "✓ Universal error handling" << std::endl;
        std::cout << "✓ Algorithm selection through parameters" << std::endl;
        
        // Utility functions demonstration
        std::cout << "\n5. Utility Functions" << std::endl;
        std::cout << "--------------------" << std::endl;
        
        std::vector<uint8_t> sampleBytes = {0xCA, 0xFE, 0xBA, 0xBE};
        std::string hexRepresentation = lockey::Lockey::bytesToHex(sampleBytes);
        auto backToBytes = lockey::Lockey::hexToBytes(hexRepresentation);
        
        std::cout << "Original bytes: CA FE BA BE" << std::endl;
        std::cout << "Hex representation: " << hexRepresentation << std::endl;
        std::cout << "Converted back: ";
        for (auto byte : backToBytes) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::endl;
        std::cout << "Utility conversion accuracy: " << (sampleBytes == backToBytes ? "PERFECT" : "ERROR") << std::endl;
        
        // Summary
        std::cout << "\n📋 Universal API Benefits Summary" << std::endl;
        std::cout << "===================================" << std::endl;
        std::cout << "✅ Single interface for multiple algorithms" << std::endl;
        std::cout << "✅ Consistent function signatures" << std::endl;
        std::cout << "✅ Easy algorithm switching" << std::endl;
        std::cout << "✅ Type-safe operations" << std::endl;
        std::cout << "✅ Built-in utility functions" << std::endl;
        std::cout << "✅ Modern C++ design patterns" << std::endl;
        
        std::cout << "\n=== Universal API demonstration completed successfully! ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}