#pragma once
#include <vector>
#include <string>
#include <memory>
#include <variant>

namespace lockey {
namespace crypto {

// Generic key pair structure
struct KeyPair {
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;
    std::string algorithm;
    size_t keySize;
    
    KeyPair(const std::string& algo, size_t size) 
        : algorithm(algo), keySize(size) {}
};

// Abstract base class for key generation algorithms
class KeyGenerator {
public:
    virtual ~KeyGenerator() = default;
    virtual KeyPair generateKeyPair(size_t keySize) = 0;
    virtual std::string getAlgorithmName() const = 0;
};

// Abstract base class for digital signature algorithms
class DigitalSigner {
public:
    virtual ~DigitalSigner() = default;
    virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& message, 
                                      const std::vector<uint8_t>& privateKey) = 0;
    virtual bool verify(const std::vector<uint8_t>& message, 
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& publicKey) = 0;
    virtual std::string getAlgorithmName() const = 0;
};

// Abstract base class for encryption algorithms
class Encryptor {
public:
    virtual ~Encryptor() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& publicKey) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& privateKey) = 0;
    virtual std::string getAlgorithmName() const = 0;
};

// Abstract base class for hash functions
class Hasher {
public:
    virtual ~Hasher() = default;
    virtual std::vector<uint8_t> hash(const std::vector<uint8_t>& input) = 0;
    virtual size_t getHashSize() const = 0;
    virtual std::string getAlgorithmName() const = 0;
};

} // namespace crypto
} // namespace lockey
