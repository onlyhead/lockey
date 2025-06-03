#pragma once

#include "hash_functions.hpp"
#include <memory>

namespace lockey {
namespace hash {

class HashEngine {
public:
    virtual ~HashEngine() = default;
    virtual std::vector<uint8_t> hash(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) = 0;
    virtual size_t hash_size() const = 0;
};

class SHA256Engine : public HashEngine {
public:    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) override {
        SHA256 hasher;
        return hasher.compute(data);
    }

    std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) override {
        HMAC<SHA256> hmac_instance(key);
        return hmac_instance.compute(data);
    }
    
    size_t hash_size() const override { return 32; }
};

class SHA384Engine : public HashEngine {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) override {
        SHA384 hasher;
        return hasher.compute(data);
    }
    
    std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) override {
        HMAC<SHA384> hmac_instance(key);
        return hmac_instance.compute(data);
    }
    
    size_t hash_size() const override { return 48; }
};

class SHA512Engine : public HashEngine {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) override {
        SHA512 hasher;
        return hasher.compute(data);
    }
    
    std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) override {
        HMAC<SHA512> hmac_instance(key);
        return hmac_instance.compute(data);
    }
    
    size_t hash_size() const override { return 64; }
};

} // namespace hash
} // namespace lockey
