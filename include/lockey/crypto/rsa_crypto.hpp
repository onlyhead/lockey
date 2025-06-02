#pragma once
#include "interfaces.hpp"
#include "../algorithm/cypher.hpp"
#include "../algorithm/blake2s.hpp"
#include <random>
#include <stdexcept>

namespace lockey {
namespace crypto {

struct RSAKeyPair : public KeyPair {
    Cypher n, e, d;
    
    RSAKeyPair(size_t keySize) : KeyPair("RSA", keySize) {}
    
    void updateByteArrays() {
        // Convert Cypher values to byte arrays for generic interface
        auto nBytes = n.toBytes();
        auto eBytes = e.toBytes();
        auto dBytes = d.toBytes();
        
        // Store as format: [n_size(4 bytes)][n][e_size(4 bytes)][e] for public key
        // Store as format: [n_size(4 bytes)][n][d_size(4 bytes)][d] for private key
        publicKey.clear();
        privateKey.clear();
        
        // Public key: n + e
        uint32_t nSize = static_cast<uint32_t>(nBytes.size());
        uint32_t eSize = static_cast<uint32_t>(eBytes.size());
        uint32_t dSize = static_cast<uint32_t>(dBytes.size());
        
        publicKey.insert(publicKey.end(), 
                        reinterpret_cast<uint8_t*>(&nSize), 
                        reinterpret_cast<uint8_t*>(&nSize) + sizeof(uint32_t));
        publicKey.insert(publicKey.end(), nBytes.begin(), nBytes.end());
        publicKey.insert(publicKey.end(), 
                        reinterpret_cast<uint8_t*>(&eSize), 
                        reinterpret_cast<uint8_t*>(&eSize) + sizeof(uint32_t));
        publicKey.insert(publicKey.end(), eBytes.begin(), eBytes.end());
        
        // Private key: n + d
        privateKey.insert(privateKey.end(), 
                         reinterpret_cast<uint8_t*>(&nSize), 
                         reinterpret_cast<uint8_t*>(&nSize) + sizeof(uint32_t));
        privateKey.insert(privateKey.end(), nBytes.begin(), nBytes.end());
        privateKey.insert(privateKey.end(), 
                         reinterpret_cast<uint8_t*>(&dSize), 
                         reinterpret_cast<uint8_t*>(&dSize) + sizeof(uint32_t));
        privateKey.insert(privateKey.end(), dBytes.begin(), dBytes.end());
    }
};

class RSAKeyGenerator : public KeyGenerator {
public:
    KeyPair generateKeyPair(size_t keySize) override {
        RSAKeyPair keyPair(keySize);
        
        Cypher one(1);
        Cypher eVal(65537);
        Cypher p = randomPrime(keySize / 2);
        Cypher q = randomPrime(keySize / 2);
        
        keyPair.n = p * q;
        keyPair.e = eVal;
        
        Cypher phi = (p - one) * (q - one);
        keyPair.d = modInverse(eVal, phi);
        
        keyPair.updateByteArrays();
        return keyPair;
    }
    
    std::string getAlgorithmName() const override {
        return "RSA";
    }

private:
    static Cypher modInverse(const Cypher &a, const Cypher &m) {
        // Extended Euclidean Algorithm
        Cypher old_r = a, r = m;
        Cypher old_s(1), s(0);
        
        while (!r.isZero()) {
            Cypher quotient = old_r / r;
            Cypher temp = r;
            r = old_r - quotient * r;
            old_r = temp;
            
            temp = s;
            if (quotient * s <= old_s) {
                s = old_s - quotient * s;
            } else {
                Cypher diff = quotient * s - old_s;
                Cypher cycles = (diff + m - Cypher(1)) / m;
                s = old_s + cycles * m - quotient * s;
            }
            old_s = temp;
        }
        
        if (old_r != Cypher(1)) {
            return Cypher(0);
        }
        
        return old_s % m;
    }
    
    static bool isPrime(const Cypher &n, int iterations = 5) {
        if (n == Cypher(2) || n == Cypher(3)) return true;
        if (n.isZero()) return false;
        if (n.isEven()) return false;
        
        Cypher d = n - Cypher(1);
        int r = 0;
        while (d.isEven()) {
            d = d >> 1;
            ++r;
        }
        
        std::random_device rd;
        std::mt19937_64 gen(rd());
        for (int i = 0; i < iterations; ++i) {
            Cypher a = Cypher::randomRange(Cypher(2), n - Cypher(2));
            if (!millerRabin(n, a, d, r)) return false;
        }
        return true;
    }
    
    static bool millerRabin(const Cypher &n, const Cypher &a, const Cypher &d, int r) {
        Cypher x = a.modExp(d, n);
        if (x == Cypher(1) || x == n - Cypher(1)) return true;
        Cypher temp = x;
        for (int i = 1; i < r; ++i) {
            temp = (temp * temp) % n;
            if (temp == n - Cypher(1)) return true;
        }
        return false;
    }
    
    static Cypher randomPrime(size_t bitLength) {
        Cypher p;
        do {
            p = Cypher::randomBits(bitLength);
        } while (!isPrime(p));
        return p;
    }
};

class RSADigitalSigner : public DigitalSigner {
public:
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message, 
                              const std::vector<uint8_t>& privateKey) override {
        auto [n, d] = extractPrivateKeyComponents(privateKey);
        
        // Hash the message
        uint8_t hash[32];
        blake2s(hash, message.data(), message.size());
        Cypher hashBig(std::vector<uint8_t>(hash, hash + 32));
        
        // Sign the hash
        Cypher signature = hashBig.modExp(d, n);
        return signature.toBytes();
    }
    
    bool verify(const std::vector<uint8_t>& message, 
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& publicKey) override {
        auto [n, e] = extractPublicKeyComponents(publicKey);
        
        // Hash the message
        uint8_t hash[32];
        blake2s(hash, message.data(), message.size());
        Cypher hashBig(std::vector<uint8_t>(hash, hash + 32));
        
        // Verify signature
        Cypher sig(signature);
        Cypher recovered = sig.modExp(e, n);
        return recovered == hashBig;
    }
    
    std::string getAlgorithmName() const override {
        return "RSA-BLAKE2s";
    }

private:
    std::pair<Cypher, Cypher> extractPublicKeyComponents(const std::vector<uint8_t>& publicKey) {
        // Extract n and e from public key format: [n_size(4 bytes)][n][e_size(4 bytes)][e]
        if (publicKey.size() < 8) {
            throw std::runtime_error("Invalid public key format");
        }
        
        uint32_t nSize = *reinterpret_cast<const uint32_t*>(publicKey.data());
        
        if (publicKey.size() < 8 + nSize) {
            throw std::runtime_error("Invalid public key format");
        }
        
        std::vector<uint8_t> nBytes(publicKey.begin() + 4, 
                                   publicKey.begin() + 4 + nSize);
        
        uint32_t eSize = *reinterpret_cast<const uint32_t*>(publicKey.data() + 4 + nSize);
        std::vector<uint8_t> eBytes(publicKey.begin() + 8 + nSize, 
                                   publicKey.end());
        
        return {Cypher(nBytes), Cypher(eBytes)};
    }
    
    std::pair<Cypher, Cypher> extractPrivateKeyComponents(const std::vector<uint8_t>& privateKey) {
        // Extract n and d from private key format: [n_size(4 bytes)][n][d_size(4 bytes)][d]
        if (privateKey.size() < 8) {
            throw std::runtime_error("Invalid private key format");
        }
        
        uint32_t nSize = *reinterpret_cast<const uint32_t*>(privateKey.data());
        
        if (privateKey.size() < 8 + nSize) {
            throw std::runtime_error("Invalid private key format");
        }
        
        std::vector<uint8_t> nBytes(privateKey.begin() + 4, 
                                   privateKey.begin() + 4 + nSize);
        
        uint32_t dSize = *reinterpret_cast<const uint32_t*>(privateKey.data() + 4 + nSize);
        std::vector<uint8_t> dBytes(privateKey.begin() + 8 + nSize, 
                                   privateKey.end());
        
        return {Cypher(nBytes), Cypher(dBytes)};
    }
};

class RSAEncryptor : public Encryptor {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& publicKey) override {
        auto [n, e] = extractPublicKeyComponents(publicKey);
        
        if (plaintext.empty()) return {};
        
        Cypher message(plaintext);
        
        // Ensure message is smaller than n
        if (message >= n) {
            throw std::runtime_error("Message too large for key size");
        }
        
        Cypher encrypted = message.modExp(e, n);
        return encrypted.toBytes();
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const std::vector<uint8_t>& privateKey) override {
        auto [n, d] = extractPrivateKeyComponents(privateKey);
        
        if (ciphertext.empty()) return {};
        
        Cypher encrypted(ciphertext);
        Cypher decrypted = encrypted.modExp(d, n);
        
        return decrypted.toBytes();
    }
    
    std::string getAlgorithmName() const override {
        return "RSA";
    }

private:
    std::pair<Cypher, Cypher> extractPublicKeyComponents(const std::vector<uint8_t>& publicKey) {
        // Extract n and e from public key format: [n_size(4 bytes)][n][e_size(4 bytes)][e]
        if (publicKey.size() < 8) {
            throw std::runtime_error("Invalid public key format");
        }
        
        uint32_t nSize = *reinterpret_cast<const uint32_t*>(publicKey.data());
        
        if (publicKey.size() < 8 + nSize) {
            throw std::runtime_error("Invalid public key format");
        }
        
        std::vector<uint8_t> nBytes(publicKey.begin() + 4, 
                                   publicKey.begin() + 4 + nSize);
        
        uint32_t eSize = *reinterpret_cast<const uint32_t*>(publicKey.data() + 4 + nSize);
        std::vector<uint8_t> eBytes(publicKey.begin() + 8 + nSize, 
                                   publicKey.end());
        
        return {Cypher(nBytes), Cypher(eBytes)};
    }
    
    std::pair<Cypher, Cypher> extractPrivateKeyComponents(const std::vector<uint8_t>& privateKey) {
        // Extract n and d from private key format: [n_size(4 bytes)][n][d_size(4 bytes)][d]
        if (privateKey.size() < 8) {
            throw std::runtime_error("Invalid private key format");
        }
        
        uint32_t nSize = *reinterpret_cast<const uint32_t*>(privateKey.data());
        
        if (privateKey.size() < 8 + nSize) {
            throw std::runtime_error("Invalid private key format");
        }
        
        std::vector<uint8_t> nBytes(privateKey.begin() + 4, 
                                   privateKey.begin() + 4 + nSize);
        
        uint32_t dSize = *reinterpret_cast<const uint32_t*>(privateKey.data() + 4 + nSize);
        std::vector<uint8_t> dBytes(privateKey.begin() + 8 + nSize, 
                                   privateKey.end());
        
        return {Cypher(nBytes), Cypher(dBytes)};
    }
};

} // namespace crypto
} // namespace lockey
