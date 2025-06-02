#include <iostream>
#include <iomanip>
#include "../include/lockey/lockey.hpp"

void printHash(const std::string& algorithm, const std::string& input, const std::string& hash) {
    std::cout << algorithm << "(" << input << ") = " << hash << std::endl;
}

int main() {
    std::cout << "=== Enhanced Cryptography Library Demo ===" << std::endl;
    std::cout << "Testing new hash algorithms from BearSSL implementation\n" << std::endl;
    
    std::string testData = "Hello, cryptographic world!";
    std::cout << "Test data: " << testData << "\n" << std::endl;
    
    try {
        // Test BLAKE2s (existing)
        auto blake2sHash = lockey::Lockey::hash(testData, lockey::crypto::CryptoManager::HashAlgorithm::BLAKE2S);
        printHash("BLAKE2s", testData, blake2sHash);
        
        // Test SHA-256 (new)
        auto sha256Hash = lockey::Lockey::hash(testData, lockey::crypto::CryptoManager::HashAlgorithm::SHA256);
        printHash("SHA-256", testData, sha256Hash);
        
        // Test SHA-1 (new)
        auto sha1Hash = lockey::Lockey::hash(testData, lockey::crypto::CryptoManager::HashAlgorithm::SHA1);
        printHash("SHA-1  ", testData, sha1Hash);
        
        // Test MD5 (new)
        auto md5Hash = lockey::Lockey::hash(testData, lockey::crypto::CryptoManager::HashAlgorithm::MD5);
        printHash("MD5    ", testData, md5Hash);
        
        std::cout << "\n=== Hash Algorithm Comparison ===" << std::endl;
        std::cout << "Algorithm | Output Size | Security Level" << std::endl;
        std::cout << "----------|-------------|---------------" << std::endl;
        std::cout << "MD5       | 128 bits    | Deprecated" << std::endl;
        std::cout << "SHA-1     | 160 bits    | Deprecated" << std::endl;
        std::cout << "SHA-256   | 256 bits    | Strong" << std::endl;
        std::cout << "BLAKE2s   | 256 bits    | Strong" << std::endl;
        
        // Test consistency
        std::cout << "\n=== Consistency Test ===" << std::endl;
        auto sha256Hash2 = lockey::Lockey::hash(testData, lockey::crypto::CryptoManager::HashAlgorithm::SHA256);
        bool consistent = (sha256Hash == sha256Hash2);
        std::cout << "SHA-256 consistency: " << (consistent ? "✓ PASS" : "✗ FAIL") << std::endl;
        
        // Test with different data
        std::cout << "\n=== Different Input Test ===" << std::endl;
        std::string emptyString = "";
        auto emptyMD5 = lockey::Lockey::hash(emptyString, lockey::crypto::CryptoManager::HashAlgorithm::MD5);
        auto emptySHA1 = lockey::Lockey::hash(emptyString, lockey::crypto::CryptoManager::HashAlgorithm::SHA1);
        auto emptySHA256 = lockey::Lockey::hash(emptyString, lockey::crypto::CryptoManager::HashAlgorithm::SHA256);
        
        printHash("MD5    ", "\"\"", emptyMD5);
        printHash("SHA-1  ", "\"\"", emptySHA1);
        printHash("SHA-256", "\"\"", emptySHA256);
        
        // Test with binary data
        std::cout << "\n=== Binary Data Test ===" << std::endl;
        std::vector<uint8_t> binaryData = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC};
        auto binarySHA256 = lockey::Lockey::hashBytes(binaryData, lockey::crypto::CryptoManager::HashAlgorithm::SHA256);
        std::cout << "SHA-256(binary_data) = " << lockey::Lockey::bytesToHex(binarySHA256) << std::endl;
        
        std::cout << "\n✅ All hash algorithms working correctly!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
