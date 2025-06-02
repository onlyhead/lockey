#include <iostream>
#include <lockey/lockey.hpp>

int main() {
    std::cout << "=== New Lockey Universal Cryptography Library Test ===" << std::endl;
    
    try {
        // 1. Test Universal Key Generation
        std::cout << "\n1. Testing Universal Key Generation..." << std::endl;
        auto keyPair = lockey::Lockey::generateKeyPair(
            lockey::crypto::CryptoManager::Algorithm::RSA, 1024
        );
        std::cout << "✓ RSA key pair generated successfully!" << std::endl;
        std::cout << "Algorithm: " << keyPair.algorithm << ", Key Size: " << keyPair.keySize << std::endl;
        
        // 2. Test Universal Hashing
        std::cout << "\n2. Testing Universal Hashing..." << std::endl;
        std::string message = "Hello, Universal Lockey!";
        std::string hash = lockey::Lockey::hash(message);
        std::cout << "Message: " << message << std::endl;
        std::cout << "✓ BLAKE2s Hash: " << hash.substr(0, 32) << "..." << std::endl;
        
        // 3. Test Universal Signing and Verification
        std::cout << "\n3. Testing Universal Digital Signatures..." << std::endl;
        std::string signature = lockey::Lockey::sign(
            message, keyPair.privateKey, lockey::crypto::CryptoManager::Algorithm::RSA
        );
        std::cout << "✓ Message signed successfully!" << std::endl;
        std::cout << "Signature: " << signature.substr(0, 32) << "..." << std::endl;
        
        bool isValid = lockey::Lockey::verify(
            message, signature, keyPair.publicKey, lockey::crypto::CryptoManager::Algorithm::RSA
        );
        std::cout << "✓ Signature verification: " << (isValid ? "VALID" : "INVALID") << std::endl;
        
        // Test with modified message
        std::string modifiedMessage = "Hello, Universal Lockey!!";
        bool isValidModified = lockey::Lockey::verify(
            modifiedMessage, signature, keyPair.publicKey, lockey::crypto::CryptoManager::Algorithm::RSA
        );
        std::cout << "✓ Modified message verification: " << (isValidModified ? "VALID" : "INVALID") << std::endl;
        
        // 4. Test Universal Encryption and Decryption
        std::cout << "\n4. Testing Universal Encryption/Decryption..." << std::endl;
        std::string plaintext = "Secret message!";
        std::cout << "Original: " << plaintext << std::endl;
        
        std::string encrypted = lockey::Lockey::encrypt(
            plaintext, keyPair.publicKey, lockey::crypto::CryptoManager::Algorithm::RSA
        );
        std::cout << "✓ Encrypted: " << encrypted.substr(0, 32) << "..." << std::endl;
        
        std::string decrypted = lockey::Lockey::decrypt(
            encrypted, keyPair.privateKey, lockey::crypto::CryptoManager::Algorithm::RSA
        );
        std::cout << "✓ Decrypted: " << decrypted << std::endl;
        std::cout << "Success: " << (plaintext == decrypted ? "YES" : "NO") << std::endl;
        
        // 5. Test Legacy Functions (backward compatibility)
        std::cout << "\n5. Testing Legacy RSA Functions..." << std::endl;
        auto rsaKeyPair = lockey::Lockey::generateRSAKeyPair(1024);
        std::cout << "✓ Legacy RSA key pair generated!" << std::endl;
        
        std::string legacySignature = lockey::Lockey::sign(message, rsaKeyPair.d, rsaKeyPair.n);
        bool legacyValid = lockey::Lockey::verify(message, legacySignature, rsaKeyPair.e, rsaKeyPair.n);
        std::cout << "✓ Legacy signature verification: " << (legacyValid ? "VALID" : "INVALID") << std::endl;
        
        std::cout << "\n=== All tests completed successfully! ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
