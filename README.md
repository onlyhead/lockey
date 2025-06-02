
# Lockey

A lightweight, header-only C++20 encrypt/decrypt sign/verify mirror key library

## Overview

Lockey provides a simple, universal interface for cryptographic operations including key generation, encryption/decryption, signing/verification, and hashing. It also includes comprehensive support for key management through file IO and string conversion.

## Features

- Key pair generation (RSA)
- Message encryption and decryption
- Digital signatures
- Hashing (BLAKE2s)
- Key management (save/load keys to/from files)
- String conversions for keys

## Installation

Lockey is a header-only library, so you can simply include it in your project:

```cpp
#include "lockey/lockey.hpp"
```

### CMake Integration

```cmake
# Add as a submodule
add_subdirectory(path/to/lockey)

# Link to your target
target_link_libraries(your_target PRIVATE lockey::lockey)
```

## Quick Start

```cpp
#include "lockey/lockey.hpp"
#include <iostream>

int main() {
    // Generate a key pair (smaller key for demo purposes)
    auto keyPair = lockey::Lockey::generateKeyPair(lockey::crypto::CryptoManager::Algorithm::RSA, 512);
    
    // Sign a message
    std::string message = "Hello, world!";
    std::string signature = lockey::Lockey::sign(message, keyPair.privateKey);
    
    // Verify the signature
    bool isValid = lockey::Lockey::verify(message, signature, keyPair.publicKey);
    std::cout << "Signature valid: " << (isValid ? "YES" : "NO") << std::endl;
    
    // Encrypt a message
    std::string encrypted = lockey::Lockey::encrypt(message, keyPair.publicKey);
    
    // Decrypt the message
    std::string decrypted = lockey::Lockey::decrypt(encrypted, keyPair.privateKey);
    std::cout << "Decrypted: " << decrypted << std::endl;
    
    return 0;
}
```

## Key Management Tutorial

Lockey provides a comprehensive set of functions for managing cryptographic keys. Here's how to use them:

### Working with Key Pairs

**Generating a Key Pair**

```cpp
// Generate a 512-bit RSA key pair (use 2048+ bits for production)
auto keyPair = lockey::Lockey::generateKeyPair(lockey::crypto::CryptoManager::Algorithm::RSA, 512);
```

**Saving a Key Pair to a File**

```cpp
// Save the key pair to a binary file
std::string filePath = "my_keypair.key";
bool success = lockey::Lockey::saveKeyPairToFile(keyPair, filePath);
```

**Loading a Key Pair from a File**

```cpp
// Load the key pair from a binary file
auto loadedKeyPair = lockey::Lockey::loadKeyPairFromFile(filePath);
```

### Working with Public Keys

**Saving a Public Key to a File**

```cpp
// Save only the public key to a file
std::string pubKeyFile = "public.key";
bool success = lockey::Lockey::savePublicKeyToFile(keyPair, pubKeyFile);

// Alternative: Save with explicit parameters
success = lockey::Lockey::savePublicKeyToFile(
    keyPair.publicKey, 
    "RSA",
    512, // key size in bits
    pubKeyFile
);
```

**Loading a Public Key from a File**

```cpp
// Load the public key from a file (returns a tuple of key, algorithm, and key size)
auto [publicKey, algorithm, keySize] = lockey::Lockey::loadPublicKeyFromFile(pubKeyFile);
```

### String Conversions

**Converting Keys to Strings**

```cpp
// Convert a key to a hexadecimal string
std::string pubKeyString = lockey::Lockey::keyToString(keyPair.publicKey);
std::string privKeyString = lockey::Lockey::keyToString(keyPair.privateKey);
```

**Converting Strings to Keys**

```cpp
// Convert a hexadecimal string back to a key
auto reconvertedPubKey = lockey::Lockey::stringToKey(pubKeyString);
```

**Converting a Key Pair to a String**

```cpp
// Convert the entire key pair to a string representation
std::string keyPairStr = lockey::Lockey::keyPairToString(keyPair);
// This produces a human-readable format:
// Algorithm: RSA
// Key Size: 512
// Public Key: [hex representation]
// Private Key: [hex representation]
```

**Parsing a Key Pair from a String**

```cpp
// Convert the string representation back to a key pair
auto reconvertedKeyPair = lockey::Lockey::keyPairFromString(keyPairStr);
```

### Binary Data Conversion

```cpp
// Convert binary data to hexadecimal string
std::vector<uint8_t> binaryData = {0x01, 0x02, 0x03};
std::string hexString = lockey::Lockey::bytesToHex(binaryData);  // "010203"

// Convert hexadecimal string to binary data
std::vector<uint8_t> convertedBack = lockey::Lockey::hexToBytes(hexString);
```

For more advanced usage, check the examples directory in the repository.

## Building the Examples

```bash
mkdir -p build && cd build
cmake .. -DLOCKEY_BUILD_EXAMPLES=ON
make
```

## License

[License Information]
