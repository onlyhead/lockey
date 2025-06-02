#include <iostream>
#include <iomanip>
#include <string>
#include <filesystem>
#include "lockey/lockey.hpp"

void printHexData(const std::string& label, const std::string& hexData, size_t maxLength = 32) {
    std::cout << label << ": ";
    if (hexData.length() <= maxLength) {
        std::cout << hexData << std::endl;
    } else {
        std::cout << hexData.substr(0, maxLength) << "... (" << hexData.length() << " chars total)" << std::endl;
    }
}

int main() {
    std::cout << "=== Lockey Key IO Demo ===" << std::endl;
    
    try {
        // Create temporary filenames for our test
        std::string keypairFile = "temp_keypair.key";
        std::string pubkeyFile = "temp_pubkey.key";
        
        std::cout << "\n🔑 Generating a new key pair (512 bits)..." << std::endl;
        auto keyPair = lockey::Lockey::generateKeyPair(lockey::crypto::CryptoManager::Algorithm::RSA, 512);
        
        std::cout << "Generated key pair:" << std::endl;
        std::cout << "  Public key size: " << keyPair.publicKey.size() << " bytes" << std::endl;
        std::cout << "  Private key size: " << keyPair.privateKey.size() << " bytes" << std::endl;
        printHexData("  Public key (hex)", lockey::Lockey::bytesToHex(keyPair.publicKey), 64);
        printHexData("  Private key (hex)", lockey::Lockey::bytesToHex(keyPair.privateKey), 64);
        
        // 1. Save key pair to file
        std::cout << "\n💾 Saving key pair to file: " << keypairFile << std::endl;
        if (lockey::Lockey::saveKeyPairToFile(keyPair, keypairFile)) {
            std::cout << "✅ Key pair saved successfully!" << std::endl;
        } else {
            std::cout << "❌ Failed to save key pair!" << std::endl;
            return 1;
        }
        
        // 2. Load key pair from file
        std::cout << "\n📂 Loading key pair from file..." << std::endl;
        auto loadedKeyPair = lockey::Lockey::loadKeyPairFromFile(keypairFile);
        
        std::cout << "Loaded key pair:" << std::endl;
        std::cout << "  Public key size: " << loadedKeyPair.publicKey.size() << " bytes" << std::endl;
        std::cout << "  Private key size: " << loadedKeyPair.privateKey.size() << " bytes" << std::endl;
        
        // Verify keys match
        bool pubKeysMatch = (keyPair.publicKey == loadedKeyPair.publicKey);
        bool privKeysMatch = (keyPair.privateKey == loadedKeyPair.privateKey);
        
        std::cout << "  Public keys match: " << (pubKeysMatch ? "✅ YES" : "❌ NO") << std::endl;
        std::cout << "  Private keys match: " << (privKeysMatch ? "✅ YES" : "❌ NO") << std::endl;
        
        // 3. Save only public key to file
        std::cout << "\n💾 Saving public key to file: " << pubkeyFile << std::endl;
        if (lockey::Lockey::savePublicKeyToFile(keyPair, pubkeyFile)) {
            std::cout << "✅ Public key saved successfully!" << std::endl;
        } else {
            std::cout << "❌ Failed to save public key!" << std::endl;
            return 1;
        }
        
        // 4. Load public key from file
        std::cout << "\n📂 Loading public key from file..." << std::endl;
        auto [loadedPubKey, algorithm, keySize] = lockey::Lockey::loadPublicKeyFromFile(pubkeyFile);
        
        std::cout << "Loaded public key:" << std::endl;
        std::cout << "  Algorithm: " << algorithm << std::endl;
        std::cout << "  Key size: " << keySize << " bits" << std::endl;
        std::cout << "  Public key size: " << loadedPubKey.size() << " bytes" << std::endl;
        
        // Verify public key matches
        bool pubKeyMatches = (keyPair.publicKey == loadedPubKey);
        std::cout << "  Public key matches original: " << (pubKeyMatches ? "✅ YES" : "❌ NO") << std::endl;
        
        // 5. Convert key to string and back
        std::cout << "\n🔄 Converting keys to string and back..." << std::endl;
        
        std::string pubKeyStr = lockey::Lockey::keyToString(keyPair.publicKey);
        std::cout << "Public key as string:" << std::endl;
        printHexData("  ", pubKeyStr, 64);
        
        auto reconvertedPubKey = lockey::Lockey::stringToKey(pubKeyStr);
        bool pubKeyReconversionMatch = (keyPair.publicKey == reconvertedPubKey);
        std::cout << "  Public key reconversion match: " << (pubKeyReconversionMatch ? "✅ YES" : "❌ NO") << std::endl;
        
        // 6. Convert entire KeyPair to string and back
        std::cout << "\n🔄 Converting entire key pair to string and back..." << std::endl;
        
        std::string keyPairStr = lockey::Lockey::keyPairToString(keyPair);
        std::cout << "Key pair as string:" << std::endl;
        std::cout << "-------------" << std::endl;
        std::cout << keyPairStr << std::endl;
        std::cout << "-------------" << std::endl;
        
        auto reconvertedKeyPair = lockey::Lockey::keyPairFromString(keyPairStr);
        bool keyPairReconversionMatch = (keyPair.publicKey == reconvertedKeyPair.publicKey && 
                                       keyPair.privateKey == reconvertedKeyPair.privateKey);
        std::cout << "  Key pair reconversion match: " << (keyPairReconversionMatch ? "✅ YES" : "❌ NO") << std::endl;
        
        // Clean up temp files
        std::filesystem::remove(keypairFile);
        std::filesystem::remove(pubkeyFile);
        std::cout << "\n🧹 Temporary files cleaned up." << std::endl;
        
        std::cout << "\n=== Key IO Demo completed successfully! ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error during key IO demo: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
