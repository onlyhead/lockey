#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include "lockey/lockey.hpp"

// Helper function to print hex data nicely
void printHexData(const std::string& label, const std::string& hexData, size_t maxLength = 32) {
    std::cout << label << ": ";
    if (hexData.length() <= maxLength) {
        std::cout << hexData << std::endl;
    } else {
        std::cout << hexData.substr(0, maxLength) << "... (" << hexData.length() << " chars total)" << std::endl;
    }
}

// Helper function to measure execution time
template<typename Func>
void measureTime(const std::string& operation, Func&& func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "⏱️  " << operation << " took " << duration.count() << " μs" << std::endl;
}

int main() {
    std::cout << "=== Lockey Debug and Performance Testing ===" << std::endl;
    
    try {
        // Performance testing
        std::cout << "\n📊 Performance Testing" << std::endl;
        std::cout << "------------------------" << std::endl;
        
        lockey::crypto::KeyPair keyPair("", 0);  // Initialize with empty values
        measureTime("Key pair generation", [&]() {
            keyPair = lockey::Lockey::generateKeyPair();
        });
        
        std::string testMessage = "Performance test message for timing measurements";
        std::string signature, encrypted;
        
        measureTime("Message signing", [&]() {
            signature = lockey::Lockey::sign(testMessage, keyPair.privateKey);
        });
        
        measureTime("Signature verification", [&]() {
            lockey::Lockey::verify(testMessage, signature, keyPair.publicKey);
        });
        
        measureTime("Message encryption", [&]() {
            encrypted = lockey::Lockey::encrypt(testMessage, keyPair.publicKey);
        });
        
        measureTime("Message decryption", [&]() {
            lockey::Lockey::decrypt(encrypted, keyPair.privateKey);
        });
        
        std::string hashResult;
        measureTime("Hashing (BLAKE2s)", [&]() {
            hashResult = lockey::Lockey::hash(testMessage);
        });
        
        // Data format testing
        std::cout << "\n🔍 Data Format Testing" << std::endl;
        std::cout << "------------------------" << std::endl;
        
        // Test hex conversion utilities
        std::vector<uint8_t> testBytes = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        std::string hexString = lockey::Lockey::bytesToHex(testBytes);
        auto convertedBack = lockey::Lockey::hexToBytes(hexString);
        
        std::cout << "Original bytes: ";
        for (auto byte : testBytes) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::endl;
        printHexData("Hex string", hexString);
        
        std::cout << "Converted back: ";
        for (auto byte : convertedBack) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::endl;
        std::cout << "Conversion accuracy: " << (testBytes == convertedBack ? "✅ PASS" : "❌ FAIL") << std::endl;
        
        // Key information display
        std::cout << "\n🔑 Key Information" << std::endl;
        std::cout << "-------------------" << std::endl;
        std::cout << "Public key size: " << keyPair.publicKey.size() << " bytes" << std::endl;
        std::cout << "Private key size: " << keyPair.privateKey.size() << " bytes" << std::endl;
        printHexData("Public key (hex)", lockey::Lockey::bytesToHex(keyPair.publicKey), 64);
        printHexData("Private key (hex)", lockey::Lockey::bytesToHex(keyPair.privateKey), 64);
        
        // Signature and encryption data
        std::cout << "\n📝 Cryptographic Data" << std::endl;
        std::cout << "----------------------" << std::endl;
        printHexData("Signature", signature, 64);
        printHexData("Encrypted data", encrypted, 64);
        printHexData("Hash (BLAKE2s)", hashResult);
        
        // Edge case testing
        std::cout << "\n🧪 Edge Case Testing" << std::endl;
        std::cout << "---------------------" << std::endl;
        
        // Test empty string
        std::string emptyHash = lockey::Lockey::hash("");
        std::cout << "Empty string hash: " << emptyHash << std::endl;
        
        // Test long message
        std::string longMessage(1000, 'A');
        std::string longSignature, longEncrypted;
        
        measureTime("Long message signing", [&]() {
            longSignature = lockey::Lockey::sign(longMessage, keyPair.privateKey);
        });
        
        bool longVerification = lockey::Lockey::verify(longMessage, longSignature, keyPair.publicKey);
        std::cout << "Long message verification: " << (longVerification ? "✅ PASS" : "❌ FAIL") << std::endl;
        
        // Test binary data with various patterns
        std::cout << "\n🔢 Binary Data Testing" << std::endl;
        std::cout << "-----------------------" << std::endl;
        
        // Test all zeros
        std::vector<uint8_t> zeroData(32, 0x00);
        auto zeroHash = lockey::Lockey::hashBytes(zeroData);
        printHexData("Zero data hash", lockey::Lockey::bytesToHex(zeroHash));
        
        // Test all ones
        std::vector<uint8_t> oneData(32, 0xFF);
        auto oneHash = lockey::Lockey::hashBytes(oneData);
        printHexData("0xFF data hash", lockey::Lockey::bytesToHex(oneHash));
        
        // Test random-like pattern
        std::vector<uint8_t> patternData;
        for (int i = 0; i < 32; ++i) {
            patternData.push_back(static_cast<uint8_t>(i * 7 + 13)); // Simple pattern
        }
        auto patternHash = lockey::Lockey::hashBytes(patternData);
        printHexData("Pattern data hash", lockey::Lockey::bytesToHex(patternHash));
        
        // Consistency testing
        std::cout << "\n🔄 Consistency Testing" << std::endl;
        std::cout << "-----------------------" << std::endl;
        
        // Test multiple hashes of same data
        std::string data = "Consistency test data";
        std::vector<std::string> hashes;
        for (int i = 0; i < 5; ++i) {
            hashes.push_back(lockey::Lockey::hash(data));
        }
        
        bool allSame = true;
        for (size_t i = 1; i < hashes.size(); ++i) {
            if (hashes[i] != hashes[0]) {
                allSame = false;
                break;
            }
        }
        std::cout << "Hash consistency across 5 runs: " << (allSame ? "✅ PASS" : "❌ FAIL") << std::endl;
        
        std::cout << "\n=== Debug testing completed ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error during debug testing: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}