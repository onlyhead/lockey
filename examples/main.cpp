#include "lockey/lockey.hpp"
#include <iostream>
#include <iomanip>

int main() {
    std::cout << "=== Lockey Cryptography Library Demo ===" << std::endl;
    
    // 1. Key Generation
    std::cout << "\n1. Generating RSA key pair (1024-bit for demo speed)..." << std::endl;
    auto keyPair = lockey::Lockey::generateKeyPair(1024);
    std::cout << "Key generation complete!" << std::endl;
    
    // 2. Hash Function Demo
    std::cout << "\n2. Hash Function Demo" << std::endl;
    std::string message = "Hello, Lockey!";
    std::string hash = lockey::Lockey::hash(message);
    std::cout << "Message: " << message << std::endl;
    std::cout << "BLAKE2s Hash: " << hash << std::endl;
    
    // 3. Digital Signatures
    std::cout << "\n3. Digital Signature Demo" << std::endl;
    std::string signature = lockey::Lockey::sign(message, keyPair.d, keyPair.n);
    std::cout << "Signature: " << signature.substr(0, 64) << "..." << std::endl;
    
    bool isValid = lockey::Lockey::verify(message, signature, keyPair.e, keyPair.n);
    std::cout << "Signature verification: " << (isValid ? "VALID" : "INVALID") << std::endl;
    
    // Test with modified message
    std::string modifiedMessage = "Hello, Lockey!!";
    bool isValidModified = lockey::Lockey::verify(modifiedMessage, signature, keyPair.e, keyPair.n);
    std::cout << "Modified message verification: " << (isValidModified ? "VALID" : "INVALID") << std::endl;
    
    // 4. Encryption/Decryption Demo
    std::cout << "\n4. Encryption/Decryption Demo" << std::endl;
    std::string plaintext = "Secret message!";
    std::cout << "Original: " << plaintext << std::endl;
    
    std::string ciphertext = lockey::Lockey::encrypt(plaintext, keyPair.e, keyPair.n);
    std::cout << "Encrypted: " << ciphertext.substr(0, 64) << "..." << std::endl;
    
    std::string decrypted = lockey::Lockey::decrypt(ciphertext, keyPair.d, keyPair.n);
    std::cout << "Decrypted: " << decrypted << std::endl;
    
    // 5. Key Serialization Demo
    std::cout << "\n5. Key Serialization Demo" << std::endl;
    std::string serializedKey = lockey::Lockey::keyToString(keyPair);
    std::cout << "Serialized key (first 100 chars): " << serializedKey.substr(0, 100) << "..." << std::endl;
    
    auto deserializedKey = lockey::Lockey::keyFromString(serializedKey);
    std::cout << "Key deserialization: " << (deserializedKey.n == keyPair.n ? "SUCCESS" : "FAILED") << std::endl;
    
    // 6. Utility Functions Demo
    std::cout << "\n6. Utility Functions Demo" << std::endl;
    std::string testHex = "48656c6c6f";
    auto bytes = lockey::Lockey::hexToBytes(testHex);
    std::string backToHex = lockey::Lockey::bytesToHex(bytes);
    std::cout << "Hex to bytes to hex: " << testHex << " -> " << backToHex << std::endl;
    
    // Convert bytes to string to see the content
    std::string content(bytes.begin(), bytes.end());
    std::cout << "Hex content as string: " << content << std::endl;
    
    std::cout << "\n=== Demo Complete ===" << std::endl;
    return 0;
}

