#include <iostream>
#include <string>
#include <vector>
#include "lockey/lockey.hpp"

int main() {
    std::cout << "=== Lockey Cryptography Library Demo ===" << std::endl;
    
    try {
        // 1. Generate RSA key pair
        std::cout << "\n1. Generating RSA key pair..." << std::endl;
        auto keyPair = lockey::Lockey::generateKeyPair();
        std::cout << "✓ Key pair generated successfully" << std::endl;
        std::cout << "Public key size: " << keyPair.publicKey.size() << " bytes" << std::endl;
        std::cout << "Private key size: " << keyPair.privateKey.size() << " bytes" << std::endl;
        
        // 2. Message signing and verification
        std::cout << "\n2. Testing digital signatures..." << std::endl;
        std::string message = "Hello, this is a test message for digital signing!";
        std::cout << "Original message: " << message << std::endl;
        
        // Sign the message
        std::string signature = lockey::Lockey::sign(message, keyPair.privateKey);
        std::cout << "✓ Message signed" << std::endl;
        std::cout << "Signature (hex): " << signature.substr(0, 64) << "..." << std::endl;
        
        // Verify the signature
        bool isValid = lockey::Lockey::verify(message, signature, keyPair.publicKey);
        std::cout << "✓ Signature verification: " << (isValid ? "VALID" : "INVALID") << std::endl;
        
        // Test with tampered message
        std::string tamperedMessage = message + " [TAMPERED]";
        bool isTamperedValid = lockey::Lockey::verify(tamperedMessage, signature, keyPair.publicKey);
        std::cout << "✓ Tampered message verification: " << (isTamperedValid ? "VALID" : "INVALID") << std::endl;
        
        // 3. Message encryption and decryption
        std::cout << "\n3. Testing encryption/decryption..." << std::endl;
        std::string plaintext = "This is a secret message!";
        std::cout << "Original plaintext: " << plaintext << std::endl;
        
        // Encrypt the message
        std::string encrypted = lockey::Lockey::encrypt(plaintext, keyPair.publicKey);
        std::cout << "✓ Message encrypted" << std::endl;
        std::cout << "Encrypted (hex): " << encrypted.substr(0, 64) << "..." << std::endl;
        
        // Decrypt the message
        std::string decrypted = lockey::Lockey::decrypt(encrypted, keyPair.privateKey);
        std::cout << "✓ Message decrypted" << std::endl;
        std::cout << "Decrypted plaintext: " << decrypted << std::endl;
        std::cout << "Decryption successful: " << (plaintext == decrypted ? "YES" : "NO") << std::endl;
        
        // 4. Hashing
        std::cout << "\n4. Testing hashing..." << std::endl;
        std::string dataToHash = "This data will be hashed using BLAKE2s";
        std::cout << "Data to hash: " << dataToHash << std::endl;
        
        std::string hashResult = lockey::Lockey::hash(dataToHash);
        std::cout << "✓ Hash computed" << std::endl;
        std::cout << "BLAKE2s hash: " << hashResult << std::endl;
        
        // Verify hash consistency
        std::string hashResult2 = lockey::Lockey::hash(dataToHash);
        std::cout << "Hash consistency: " << (hashResult == hashResult2 ? "CONSISTENT" : "INCONSISTENT") << std::endl;
        
        // 5. Binary data operations
        std::cout << "\n5. Testing binary data operations..." << std::endl;
        std::vector<uint8_t> binaryData = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
        
        // Sign binary data
        auto binarySignature = lockey::Lockey::signBytes(binaryData, keyPair.privateKey);
        std::cout << "✓ Binary data signed" << std::endl;
        
        // Verify binary signature
        bool binaryVerified = lockey::Lockey::verifyBytes(binaryData, binarySignature, keyPair.publicKey);
        std::cout << "✓ Binary signature verification: " << (binaryVerified ? "VALID" : "INVALID") << std::endl;
        
        // Hash binary data
        auto binaryHash = lockey::Lockey::hashBytes(binaryData);
        std::cout << "✓ Binary data hashed" << std::endl;
        std::cout << "Binary hash (hex): " << lockey::Lockey::bytesToHex(binaryHash) << std::endl;
        
        std::cout << "\n=== All tests completed successfully! ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}