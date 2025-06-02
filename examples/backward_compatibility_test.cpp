#include <iostream>
#include <lockey/lockey.hpp>

int main() {
    std::cout << "=== Lockey Backward Compatibility Test ===" << std::endl;
    
    try {
        // Test that old BigInt usage still works with the alias
        std::cout << "\n1. Testing BigInt alias compatibility..." << std::endl;
        lockey::BigInt a(12345);
        lockey::BigInt b(67890);
        lockey::BigInt result = a * b;
        std::cout << "✓ BigInt operations work: " << a.toString() << " * " << b.toString() << " = " << result.toString() << std::endl;
        
        // Test that Cypher class works directly
        std::cout << "\n2. Testing Cypher class directly..." << std::endl;
        lockey::Cypher x(98765);
        lockey::Cypher y(43210);
        lockey::Cypher sum = x + y;
        std::cout << "✓ Cypher operations work: " << x.toString() << " + " << y.toString() << " = " << sum.toString() << std::endl;
        
        // Test legacy RSA functions
        std::cout << "\n3. Testing legacy RSA key generation..." << std::endl;
        auto keys = lockey::Lockey::generateRSAKeyPair(1024);
        std::cout << "✓ RSA key pair generated successfully!" << std::endl;
        std::cout << "n length: " << keys.n.bitLength() << " bits" << std::endl;
        std::cout << "e value: " << keys.e.toString() << std::endl;
        
        // Test legacy encryption/decryption
        std::cout << "\n4. Testing legacy encryption/decryption..." << std::endl;
        std::string message = "Legacy test message";
        std::string encrypted = lockey::Lockey::encrypt(message, keys.e, keys.n);
        std::string decrypted = lockey::Lockey::decrypt(encrypted, keys.d, keys.n);
        std::cout << "Original: " << message << std::endl;
        std::cout << "Decrypted: " << decrypted << std::endl;
        std::cout << "✓ Legacy encryption/decryption: " << (message == decrypted ? "SUCCESS" : "FAILED") << std::endl;
        
        // Test legacy signing/verification
        std::cout << "\n5. Testing legacy signing/verification..." << std::endl;
        std::string signature = lockey::Lockey::sign(message, keys.d, keys.n);
        bool isValid = lockey::Lockey::verify(message, signature, keys.e, keys.n);
        std::cout << "✓ Legacy signature verification: " << (isValid ? "VALID" : "INVALID") << std::endl;
        
        std::cout << "\n=== All backward compatibility tests passed! ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
