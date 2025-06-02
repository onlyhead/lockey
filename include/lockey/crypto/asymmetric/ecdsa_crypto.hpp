#pragma once
#include "../interfaces.hpp"
#include "../../algorithm/ecdsa.hpp"
#include "../../algorithm/elliptic_curve.hpp"
#include <memory>

namespace lockey {
namespace crypto {

/**
 * @brief ECDSA Key Pair for the generic crypto interface
 */
struct ECDSAKeyPair : public KeyPair {
    std::shared_ptr<ECCurve> curve;
    Cypher private_key_scalar;
    ECPoint public_key_point;
    
    ECDSAKeyPair(size_t keySize, std::shared_ptr<ECCurve> curve_ptr) 
        : KeyPair("ECDSA", keySize), curve(curve_ptr) {}
    
    void updateByteArrays() {
        // Encode private key as big-endian bytes
        auto privBytes = private_key_scalar.toBytes();
        
        // Encode public key in uncompressed format (0x04 || x || y)
        auto pubBytes = curve->encode_point(public_key_point, false);
        
        // Store curve ID and key data
        privateKey.clear();
        publicKey.clear();
        
        // Private key format: [curve_id(4 bytes)][key_size(4 bytes)][private_key]
        uint32_t curveId = static_cast<uint32_t>(curve->curve_id());
        uint32_t keySize = static_cast<uint32_t>(privBytes.size());
        
        privateKey.insert(privateKey.end(), 
                         reinterpret_cast<uint8_t*>(&curveId),
                         reinterpret_cast<uint8_t*>(&curveId) + sizeof(uint32_t));
        privateKey.insert(privateKey.end(),
                         reinterpret_cast<uint8_t*>(&keySize),
                         reinterpret_cast<uint8_t*>(&keySize) + sizeof(uint32_t));
        privateKey.insert(privateKey.end(), privBytes.begin(), privBytes.end());
        
        // Public key format: [curve_id(4 bytes)][point_size(4 bytes)][public_point]
        uint32_t pointSize = static_cast<uint32_t>(pubBytes.size());
        
        publicKey.insert(publicKey.end(),
                        reinterpret_cast<uint8_t*>(&curveId),
                        reinterpret_cast<uint8_t*>(&curveId) + sizeof(uint32_t));
        publicKey.insert(publicKey.end(),
                        reinterpret_cast<uint8_t*>(&pointSize),
                        reinterpret_cast<uint8_t*>(&pointSize) + sizeof(uint32_t));
        publicKey.insert(publicKey.end(), pubBytes.begin(), pubBytes.end());
    }
};

/**
 * @brief ECDSA Key Generator
 */
class ECDSAKeyGenerator : public KeyGenerator {
private:
    std::shared_ptr<ECCurve> curve_;
    
public:
    ECDSAKeyGenerator(std::shared_ptr<ECCurve> curve) : curve_(curve) {}
    
    KeyPair generateKeyPair(size_t keySize) override {
        // Generate ECDSA key pair
        auto ecdsaKeyPair = ECDSA::generate_key_pair(curve_);
        
        // Create our wrapper
        ECDSAKeyPair keyPair(keySize, curve_);
        keyPair.private_key_scalar = ecdsaKeyPair.private_key;
        keyPair.public_key_point = ecdsaKeyPair.public_key;
        
        keyPair.updateByteArrays();
        return keyPair;
    }
    
    std::string getAlgorithmName() const override {
        return "ECDSA-" + curve_->name();
    }
};

/**
 * @brief ECDSA Digital Signer
 */
class ECDSADigitalSigner : public DigitalSigner {
private:
    std::shared_ptr<ECCurve> curve_;
    
public:
    ECDSADigitalSigner(std::shared_ptr<ECCurve> curve) : curve_(curve) {}
    
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message, 
                              const std::vector<uint8_t>& privateKey) override {
        auto [curveId, privKeyScalar] = extractPrivateKeyComponents(privateKey);
        
        // Verify curve matches
        if (curveId != curve_->curve_id()) {
            throw std::runtime_error("Private key curve mismatch");
        }
        
        // Sign the message (ECDSA will hash it automatically)
        auto signature = ECDSA::sign_message(message, privKeyScalar, curve_);
        
        // Return DER-encoded signature
        return signature.encode_der();
    }
    
    bool verify(const std::vector<uint8_t>& message, 
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& publicKey) override {
        auto [curveId, pubKeyPoint] = extractPublicKeyComponents(publicKey);
        
        // Verify curve matches
        if (curveId != curve_->curve_id()) {
            throw std::runtime_error("Public key curve mismatch");
        }
        
        try {
            // Decode signature
            auto sig = ECDSA::Signature::decode_der(signature);
            
            // Verify the message signature
            return ECDSA::verify_message(message, sig, pubKeyPoint, curve_);
        } catch (...) {
            return false;
        }
    }
    
    std::string getAlgorithmName() const override {
        return "ECDSA-" + curve_->name();
    }

private:
    std::pair<int, Cypher> extractPrivateKeyComponents(const std::vector<uint8_t>& privateKey) {
        if (privateKey.size() < 8) {
            throw std::runtime_error("Invalid ECDSA private key format");
        }
        
        uint32_t curveId = *reinterpret_cast<const uint32_t*>(privateKey.data());
        uint32_t keySize = *reinterpret_cast<const uint32_t*>(privateKey.data() + 4);
        
        if (privateKey.size() < 8 + keySize) {
            throw std::runtime_error("Invalid ECDSA private key format");
        }
        
        std::vector<uint8_t> keyBytes(privateKey.begin() + 8,
                                     privateKey.begin() + 8 + keySize);
        
        return {static_cast<int>(curveId), Cypher(keyBytes)};
    }
    
    std::pair<int, ECPoint> extractPublicKeyComponents(const std::vector<uint8_t>& publicKey) {
        if (publicKey.size() < 8) {
            throw std::runtime_error("Invalid ECDSA public key format");
        }
        
        uint32_t curveId = *reinterpret_cast<const uint32_t*>(publicKey.data());
        uint32_t pointSize = *reinterpret_cast<const uint32_t*>(publicKey.data() + 4);
        
        if (publicKey.size() < 8 + pointSize) {
            throw std::runtime_error("Invalid ECDSA public key format");
        }
        
        std::vector<uint8_t> pointBytes(publicKey.begin() + 8,
                                       publicKey.begin() + 8 + pointSize);
        
        ECPoint point = curve_->decode_point(pointBytes);
        
        return {static_cast<int>(curveId), point};
    }
};

} // namespace crypto
} // namespace lockey
