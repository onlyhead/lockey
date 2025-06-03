#include "lockey/lockey.hpp"
#include <iostream>
#include <vector>

int main() {
    try {
        // Test basic construction
        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM);
        std::cout << "✓ Lockey construction successful" << std::endl;
        
        // Test basic encryption
        std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        std::vector<uint8_t> key = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
        };
        
        auto result = crypto.encrypt(data, key);
        if (result.success) {
            std::cout << "✓ Basic encryption test successful" << std::endl;
            std::cout << "Encrypted data size: " << result.data.size() << " bytes" << std::endl;
        } else {
            std::cout << "✗ Encryption failed: " << result.error_message << std::endl;
        }
        
        // Test hash functions
        auto hash_result = crypto.hash(data);
        if (hash_result.success) {
            std::cout << "✓ Basic hash test successful" << std::endl;
            std::cout << "Hash size: " << hash_result.data.size() << " bytes" << std::endl;
        } else {
            std::cout << "✗ Hash failed: " << hash_result.error_message << std::endl;
        }
        
        // Test hex conversion
        auto hex = crypto.to_hex(data);
        std::cout << "✓ Hex conversion: " << hex << std::endl;
        
        std::cout << "All basic tests completed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "✗ Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
