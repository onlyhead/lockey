<img align="right" width="26%" src="./misc/logo.png">

# Lockey

**A modern, zero-dependency C++20 cryptographic library with a clean api for key/cert management**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/lockey)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue)](https://en.cppreference.com/w/cpp/20)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Header Only](https://img.shields.io/badge/header--only-yes-orange)](https://github.com/yourusername/lockey)

## Overview

Lockey is a comprehensive cryptographic library designed as a drop-in replacement for OpenSSL. It provides a simple, modern C++20 interface for all common cryptographic operations while maintaining zero external dependencies. Perfect for embedded systems, containerized applications, and any codebase where you want powerful crypto without the complexity.

### 🚀 Key Features

- **Zero Dependencies**: Header-only library with no external requirements
- **OpenSSL Compatible**: Drop-in replacement for most OpenSSL chain operations
- **Modern C++20**: Clean, type-safe API with comprehensive error handling
- **Universal Algorithm Support**: RSA, ECDSA (P-256/P-384/P-521), Ed25519, multiple hash functions
- **Complete Key Management**: Generation, serialization, file I/O, format conversion
- **Production Ready**: Used in real-world blockchain and IoT applications

## Quick Start

### Installation

Simply include the header in your project:

```cpp
#include "lockey/lockey.hpp"
```

### Basic Usage

```cpp
#include "lockey/lockey.hpp"
#include <iostream>

int main() {
    // Create a crypto instance
    lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
    
    // Generate a keypair
    auto keypair = crypto.generate_keypair();
    
    // Sign a message
    std::string message = "Hello, Lockey!";
    std::vector<uint8_t> data(message.begin(), message.end());
    auto signature = crypto.sign(data, keypair.private_key);
    
    // Verify the signature
    auto verification = crypto.verify(data, signature.data, keypair.public_key);
    
    std::cout << "Signature valid: " << (verification.success ? "Yes" : "No") << std::endl;
    return 0;
}
```

## Supported Algorithms

| Algorithm | Key Generation | Signing | Encryption | Notes |
|-----------|----------------|---------|------------|-------|
| RSA-2048 | ✅ | ✅ | ✅ | Industry standard |
| RSA-4096 | ✅ | ✅ | ✅ | High security |
| ECDSA P-256 | ✅ | ✅ | ❌ | secp256r1 curve |
| ECDSA P-384 | ✅ | ✅ | ❌ | secp384r1 curve |
| ECDSA P-521 | ✅ | ✅ | ❌ | secp521r1 curve |
| Ed25519 | ✅ | ✅ | ❌ | Modern elliptic curve |

### Hash Functions

- SHA-256, SHA-384, SHA-512
- BLAKE2b
- HMAC support for all hash functions

## Complete API Reference

### Core Operations

#### 1. Key Generation

```cpp
lockey::Lockey crypto(lockey::Lockey::Algorithm::RSA_2048);
auto keypair = crypto.generate_keypair();

// Access keys
std::vector<uint8_t> private_key = keypair.private_key;
std::vector<uint8_t> public_key = keypair.public_key;
```

#### 2. Digital Signatures

```cpp
// Sign data
std::vector<uint8_t> message = {/* your data */};
auto signature = crypto.sign(message, private_key);

if (signature.success) {
    std::cout << "Signature: " << lockey::Lockey::to_hex(signature.data) << std::endl;
}

// Verify signature
auto verification = crypto.verify(message, signature.data, public_key);
std::cout << "Valid: " << verification.success << std::endl;
```

#### 3. Asymmetric Encryption (RSA only)

```cpp
// Encrypt with public key
auto encrypted = crypto.encrypt_asymmetric(message, public_key);

// Decrypt with private key  
auto decrypted = crypto.decrypt_asymmetric(encrypted.data, private_key);

std::string original(decrypted.data.begin(), decrypted.data.end());
```

#### 4. Symmetric Encryption

```cpp
// Generate symmetric key
auto key = crypto.generate_symmetric_key();

// Encrypt data
auto encrypted = crypto.encrypt_symmetric(message, key);

// Decrypt data
auto decrypted = crypto.decrypt_symmetric(encrypted.data, key);
```

#### 5. Hashing

```cpp
// Hash data
auto hash = crypto.hash(message);
std::cout << "SHA-256: " << lockey::Lockey::to_hex(hash.data) << std::endl;

// HMAC
std::vector<uint8_t> hmac_key = {/* your key */};
auto hmac = crypto.hmac(message, hmac_key);
```

### Key Management

#### Hex Conversion

```cpp
// Convert to hex string
std::string hex = lockey::Lockey::to_hex(keypair.public_key);

// Convert from hex
auto binary = lockey::Lockey::from_hex(hex);
```

#### File I/O

```cpp
// Save keys to files
crypto.save_private_key("private.key", keypair.private_key);
crypto.save_public_key("public.key", keypair.public_key);

// Load keys from files
auto loaded_private = crypto.load_private_key("private.key");
auto loaded_public = crypto.load_public_key("public.key");
```

## Algorithm Examples

### RSA-2048 Complete Example

```cpp
#include "lockey/lockey.hpp"
#include <iostream>
#include <string>

int main() {
    lockey::Lockey rsa(lockey::Lockey::Algorithm::RSA_2048);
    
    // Generate keypair
    auto keypair = rsa.generate_keypair();
    std::cout << "Generated RSA-2048 keypair" << std::endl;
    std::cout << "Private key size: " << keypair.private_key.size() << " bytes" << std::endl;
    std::cout << "Public key size: " << keypair.public_key.size() << " bytes" << std::endl;
    
    // Test signing
    std::string message = "This is a test message for RSA signing";
    std::vector<uint8_t> data(message.begin(), message.end());
    
    auto signature = rsa.sign(data, keypair.private_key);
    std::cout << "Signing: " << (signature.success ? "SUCCESS" : "FAILED") << std::endl;
    
    // Test verification
    auto verification = rsa.verify(data, signature.data, keypair.public_key);
    std::cout << "Verification: " << (verification.success ? "SUCCESS" : "FAILED") << std::endl;
    
    // Test encryption/decryption
    std::string plaintext = "Secret message to encrypt";
    std::vector<uint8_t> plain_data(plaintext.begin(), plaintext.end());
    
    auto encrypted = rsa.encrypt_asymmetric(plain_data, keypair.public_key);
    std::cout << "Encryption: " << (encrypted.success ? "SUCCESS" : "FAILED") << std::endl;
    
    if (encrypted.success) {
        auto decrypted = rsa.decrypt_asymmetric(encrypted.data, keypair.private_key);
        std::cout << "Decryption: " << (decrypted.success ? "SUCCESS" : "FAILED") << std::endl;
        
        if (decrypted.success) {
            std::string result(decrypted.data.begin(), decrypted.data.end());
            std::cout << "Roundtrip: " << (plaintext == result ? "SUCCESS" : "FAILED") << std::endl;
        }
    }
    
    return 0;
}
```

### ECDSA P-256 Example

```cpp
#include "lockey/lockey.hpp"

int main() {
    lockey::Lockey ecdsa(lockey::Lockey::Algorithm::ECDSA_P256);
    
    // Generate keypair
    auto keypair = ecdsa.generate_keypair();
    
    // Sign message
    std::string message = "ECDSA signing test";
    std::vector<uint8_t> data(message.begin(), message.end());
    auto signature = ecdsa.sign(data, keypair.private_key);
    
    // Verify signature
    auto verification = ecdsa.verify(data, signature.data, keypair.public_key);
    
    std::cout << "ECDSA P-256 signature: " << (verification.success ? "VALID" : "INVALID") << std::endl;
    return 0;
}
```

### Ed25519 Example

```cpp
#include "lockey/lockey.hpp"

int main() {
    lockey::Lockey ed25519(lockey::Lockey::Algorithm::ED25519);
    
    auto keypair = ed25519.generate_keypair();
    
    std::string message = "Ed25519 is fast and secure";
    std::vector<uint8_t> data(message.begin(), message.end());
    
    auto signature = ed25519.sign(data, keypair.private_key);
    auto verification = ed25519.verify(data, signature.data, keypair.public_key);
    
    std::cout << "Ed25519 signature: " << (verification.success ? "VALID" : "INVALID") << std::endl;
    return 0;
}
```

## OpenSSL Drop-in Replacement

Lockey can completely replace OpenSSL in most applications. Here's a comparison:

### Before (OpenSSL)
```cpp
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
// ... complex OpenSSL setup code
```

### After (Lockey)
```cpp
#include "lockey/lockey.hpp"
// That's it! Zero dependencies, clean API
```

### Chain Namespace Compatibility

For applications using the `chain::` namespace pattern, Lockey provides a complete drop-in replacement:

```cpp
// Include Lockey's chain compatibility layer
namespace chain {
    // All your existing chain:: functions work unchanged!
    inline std::string base64Encode(const std::vector<unsigned char>& data);
    inline std::vector<unsigned char> base64Decode(const std::string& encoded);
    
    class Crypto {
        std::vector<unsigned char> sign(const std::string& data);
        std::string getPublicHalf();
        // ... all existing methods
    };
    
    inline bool verify(const std::string& pemPublic, const std::string& data, 
                      const std::vector<unsigned char>& signature);
    // ... complete compatibility
}
```

## Error Handling

Lockey uses a consistent result pattern for error handling:

```cpp
struct Result {
    bool success;
    std::vector<uint8_t> data;
    std::string error_message;
};

auto result = crypto.sign(message, private_key);
if (!result.success) {
    std::cerr << "Error: " << result.error_message << std::endl;
} else {
    // Use result.data
}
```

## Performance & Security

- **Performance**: Optimized implementations with modern C++ features
- **Security**: Industry-standard algorithms with proper parameter validation
- **Memory Safety**: RAII pattern, no manual memory management required
- **Thread Safety**: Stateless design allows safe concurrent usage

## Building & Integration

### CMake Integration

```cmake
# Add to your CMakeLists.txt
include_directories(path/to/lockey/include)

# Or use FetchContent
include(FetchContent)
FetchContent_Declare(
    lockey
    GIT_REPOSITORY https://github.com/yourusername/lockey.git
    GIT_TAG main
)
FetchContent_MakeAvailable(lockey)

target_link_libraries(your_target lockey::lockey)
```

### Compiler Requirements

- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 2019+)
- No external dependencies required

## Examples & Tests

The repository includes comprehensive examples and tests:

- `examples/` - Complete usage examples for all algorithms
- `test/` - Comprehensive test suite
- `examples/openssl_comparison.cpp` - OpenSSL replacement demonstration
- `examples/chain_dropin_simple.cpp` - Drop-in chain:: namespace replacement

Build examples:
```bash
cd lockey
make
./build/openssl_comparison
```

## Use Cases

- **Blockchain Applications**: Digital signatures, key management
- **IoT Devices**: Lightweight crypto without OpenSSL overhead  
- **Embedded Systems**: Zero dependencies, small footprint
- **Microservices**: Clean API, easy integration
- **Legacy Migration**: Drop-in OpenSSL replacement

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- 📖 **Documentation**: This README and inline code comments
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/lockey/issues)  
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/lockey/discussions)

---

**Lockey** - Modern cryptography made simple. Replace OpenSSL complexity with clean C++20 design.
