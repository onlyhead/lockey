#include "lockey/lockey.hpp"
#include <iostream>

int main() {
    std::cout << "=== Debug RSA Implementation ===" << std::endl;
    
    // Test with smaller numbers first
    lockey::BigInt p(7);
    lockey::BigInt q(11);
    lockey::BigInt n = p * q; // 77
    lockey::BigInt phi = (p - lockey::BigInt(1)) * (q - lockey::BigInt(1)); // 60
    lockey::BigInt e(13); // Should be coprime to 60
    
    std::cout << "p = " << p.toString() << std::endl;
    std::cout << "q = " << q.toString() << std::endl;
    std::cout << "n = " << n.toString() << std::endl;
    std::cout << "phi = " << phi.toString() << std::endl;
    std::cout << "e = " << e.toString() << std::endl;
    
    // Test modInverse
    lockey::BigInt d = lockey::RSA::modInverse(e, phi);
    std::cout << "d = " << d.toString() << std::endl;
    
    // Test if e * d ≡ 1 (mod phi)
    lockey::BigInt test = (e * d) % phi;
    std::cout << "e * d mod phi = " << test.toString() << std::endl;
    std::cout << "Should be 1: " << (test == lockey::BigInt(1) ? "YES" : "NO") << std::endl;
    
    // Test encryption/decryption
    lockey::BigInt message(42);
    std::cout << "\nOriginal message: " << message.toString() << std::endl;
    
    lockey::BigInt encrypted = lockey::RSA::encrypt(message, e, n);
    std::cout << "Encrypted: " << encrypted.toString() << std::endl;
    
    lockey::BigInt decrypted = lockey::RSA::decrypt(encrypted, d, n);
    std::cout << "Decrypted: " << decrypted.toString() << std::endl;
    std::cout << "Correct: " << (decrypted == message ? "YES" : "NO") << std::endl;
    
    return 0;
}
