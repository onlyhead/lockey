#pragma once

#include "rsa_crypto.hpp"
#include <random>
#include <algorithm>

namespace lockey {
namespace rsa {

// Simplified BigInteger implementations (stubs for compilation)

inline BigInteger::BigInteger() : digits_{0}, negative_(false) {}

inline BigInteger::BigInteger(uint64_t value) : negative_(false) {
    if (value == 0) {
        digits_ = {0};
    } else {
        digits_.clear();
        while (value > 0) {
            digits_.push_back(value & 0xFFFFFFFF);
            value >>= 32;
        }
    }
}

inline BigInteger::BigInteger(const std::vector<uint8_t>& bytes) : negative_(false) {
    if (bytes.empty()) {
        digits_ = {0};
        return;
    }
    
    digits_.clear();
    for (size_t i = 0; i < bytes.size(); i += 4) {
        uint32_t digit = 0;
        for (size_t j = 0; j < 4 && i + j < bytes.size(); j++) {
            digit |= static_cast<uint32_t>(bytes[bytes.size() - 1 - i - j]) << (j * 8);
        }
        digits_.push_back(digit);
    }
    normalize();
}

inline BigInteger BigInteger::operator+(const BigInteger& other) const {
    // Simplified stub implementation
    BigInteger result(*this);
    return result;
}

inline BigInteger BigInteger::operator-(const BigInteger& other) const {
    // Simplified stub implementation
    BigInteger result(*this);
    return result;
}

inline BigInteger BigInteger::operator*(const BigInteger& other) const {
    // Simplified stub implementation
    BigInteger result(*this);
    return result;
}

inline BigInteger BigInteger::operator/(const BigInteger& other) const {
    // Simplified stub implementation
    BigInteger result(*this);
    return result;
}

inline BigInteger BigInteger::operator%(const BigInteger& other) const {
    // Simplified stub implementation
    BigInteger result(*this);
    return result;
}

inline bool BigInteger::operator==(const BigInteger& other) const {
    return digits_ == other.digits_ && negative_ == other.negative_;
}

inline bool BigInteger::operator!=(const BigInteger& other) const {
    return !(*this == other);
}

inline bool BigInteger::operator<(const BigInteger& other) const {
    return compare_abs(other) < 0;
}

inline bool BigInteger::operator<=(const BigInteger& other) const {
    return compare_abs(other) <= 0;
}

inline bool BigInteger::operator>(const BigInteger& other) const {
    return compare_abs(other) > 0;
}

inline bool BigInteger::operator>=(const BigInteger& other) const {
    return compare_abs(other) >= 0;
}

inline BigInteger BigInteger::mod_pow(const BigInteger& exponent, const BigInteger& modulus) const {
    // Simplified stub implementation
    return BigInteger(1);
}

inline BigInteger BigInteger::mod_inverse(const BigInteger& modulus) const {
    // Simplified stub implementation
    return BigInteger(1);
}

inline BigInteger BigInteger::gcd(const BigInteger& other) const {
    // Simplified stub implementation
    return BigInteger(1);
}

inline bool BigInteger::is_zero() const {
    return digits_.size() == 1 && digits_[0] == 0;
}

inline bool BigInteger::is_odd() const {
    return !is_zero() && (digits_[0] & 1) != 0;
}

inline size_t BigInteger::bit_length() const {
    if (is_zero()) return 0;
    
    size_t bits = (digits_.size() - 1) * 32;
    uint32_t top = digits_.back();
    while (top > 0) {
        bits++;
        top >>= 1;
    }
    return bits;
}

inline std::vector<uint8_t> BigInteger::to_bytes() const {
    if (is_zero()) return {0};
    
    std::vector<uint8_t> result;
    for (auto it = digits_.rbegin(); it != digits_.rend(); ++it) {
        uint32_t digit = *it;
        for (int i = 3; i >= 0; i--) {
            uint8_t byte = (digit >> (i * 8)) & 0xFF;
            if (!result.empty() || byte != 0) {
                result.push_back(byte);
            }
        }
    }
    return result.empty() ? std::vector<uint8_t>{0} : result;
}

inline std::string BigInteger::to_string() const {
    // Simplified hex representation
    auto bytes = to_bytes();
    std::string result;
    for (uint8_t byte : bytes) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        result += hex;
    }
    return result;
}

inline BigInteger BigInteger::generate_prime(size_t bit_length) {
    // Simplified stub - returns a small prime
    return BigInteger(17);
}

inline bool BigInteger::is_prime() const {
    // Simplified stub
    return !is_zero() && digits_[0] > 1;
}

inline void BigInteger::normalize() {
    while (digits_.size() > 1 && digits_.back() == 0) {
        digits_.pop_back();
    }
    if (digits_.size() == 1 && digits_[0] == 0) {
        negative_ = false;
    }
}

inline int BigInteger::compare_abs(const BigInteger& other) const {
    if (digits_.size() != other.digits_.size()) {
        return digits_.size() < other.digits_.size() ? -1 : 1;
    }
    
    for (auto i = digits_.rbegin(), j = other.digits_.rbegin(); 
         i != digits_.rend(); ++i, ++j) {
        if (*i != *j) {
            return *i < *j ? -1 : 1;
        }
    }
    return 0;
}

// RSA implementation stubs

inline KeyPair RSAImpl::generate_keypair() const {
    // Simplified stub implementation
    KeyPair keypair;
    keypair.key_size = key_size_;
    
    // Generate simple test values
    BigInteger e(65537);
    BigInteger p = BigInteger::generate_prime(key_size_ / 2);
    BigInteger q = BigInteger::generate_prime(key_size_ / 2);
    BigInteger n = p * q;
    BigInteger phi = (p - BigInteger(1)) * (q - BigInteger(1));
    BigInteger d = e.mod_inverse(phi);
    
    keypair.n = n.to_bytes();
    keypair.e = e.to_bytes();
    keypair.d = d.to_bytes();
    keypair.p = p.to_bytes();
    keypair.q = q.to_bytes();
    
    return keypair;
}

inline PublicKey RSAImpl::extract_public_key(const KeyPair& keypair) const {
    PublicKey pubkey;
    pubkey.n = keypair.n;
    pubkey.e = keypair.e;
    pubkey.key_size = keypair.key_size;
    return pubkey;
}

inline PrivateKey RSAImpl::extract_private_key(const KeyPair& keypair) const {
    PrivateKey privkey;
    privkey.n = keypair.n;
    privkey.d = keypair.d;
    privkey.p = keypair.p;
    privkey.q = keypair.q;
    privkey.key_size = keypair.key_size;
    return privkey;
}

// Stub implementations for other RSA methods
inline std::vector<uint8_t> RSAImpl::encrypt(const std::vector<uint8_t>& data,
                                           const PublicKey& key,
                                           PaddingScheme padding) const {
    // Simplified stub
    return data;
}

inline std::vector<uint8_t> RSAImpl::decrypt(const std::vector<uint8_t>& data,
                                           const PrivateKey& key,
                                           PaddingScheme padding) const {
    // Simplified stub
    return data;
}

inline std::vector<uint8_t> RSAImpl::sign(const std::vector<uint8_t>& hash,
                                        const PrivateKey& key,
                                        PaddingScheme padding,
                                        const std::string& hash_algorithm) const {
    // Simplified stub
    return hash;
}

inline bool RSAImpl::verify(const std::vector<uint8_t>& hash,
                          const std::vector<uint8_t>& signature,
                          const PublicKey& key,
                          PaddingScheme padding,
                          const std::string& hash_algorithm) const {
    // Simplified stub
    return true;
}

} // namespace rsa
} // namespace lockey
    
    // Process hex string in chunks of 8 characters (32 bits)
    std::string clean_hex = hex;
    if (clean_hex.size() % 8 != 0) {
        clean_hex = std::string(8 - (clean_hex.size() % 8), '0') + clean_hex;
    }
    
    for (int i = clean_hex.size() - 8; i >= 0; i -= 8) {
        std::string chunk = clean_hex.substr(i, 8);
        uint32_t digit = static_cast<uint32_t>(std::stoul(chunk, nullptr, 16));
        digits_.push_back(digit);
    }
    normalize();
}

inline BigInteger BigInteger::operator+(const BigInteger& other) const {
    if (negative_ != other.negative_) {
        if (negative_) {
            BigInteger temp = *this;
            temp.negative_ = false;
            return other - temp;
        } else {
            BigInteger temp = other;
            temp.negative_ = false;
            return *this - temp;
        }
    }
    
    BigInteger result;
    result.negative_ = negative_;
    
    size_t max_size = std::max(digits_.size(), other.digits_.size());
    result.digits_.resize(max_size + 1, 0);
    
    uint64_t carry = 0;
    for (size_t i = 0; i < max_size; i++) {
        uint64_t a = (i < digits_.size()) ? digits_[i] : 0;
        uint64_t b = (i < other.digits_.size()) ? other.digits_[i] : 0;
        uint64_t sum = a + b + carry;
        
        result.digits_[i] = static_cast<uint32_t>(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
    
    if (carry) {
        result.digits_[max_size] = static_cast<uint32_t>(carry);
    }
    
    result.normalize();
    return result;
}

inline BigInteger BigInteger::operator-(const BigInteger& other) const {
    if (negative_ != other.negative_) {
        BigInteger temp = other;
        temp.negative_ = !temp.negative_;
        return *this + temp;
    }
    
    if (negative_) {
        BigInteger temp1 = *this, temp2 = other;
        temp1.negative_ = temp2.negative_ = false;
        BigInteger result = temp2 - temp1;
        result.negative_ = !result.negative_;
        return result;
    }
    
    if (compare_abs(other) < 0) {
        BigInteger result = other - *this;
        result.negative_ = true;
        return result;
    }
    
    BigInteger result;
    result.digits_.resize(digits_.size(), 0);
    
    int64_t borrow = 0;
    for (size_t i = 0; i < digits_.size(); i++) {
        int64_t a = digits_[i];
        int64_t b = (i < other.digits_.size()) ? other.digits_[i] : 0;
        int64_t diff = a - b - borrow;
        
        if (diff < 0) {
            diff += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        
        result.digits_[i] = static_cast<uint32_t>(diff);
    }
    
    result.normalize();
    return result;
}

inline BigInteger BigInteger::operator*(const BigInteger& other) const {
    BigInteger result;
    result.negative_ = negative_ != other.negative_;
    result.digits_.resize(digits_.size() + other.digits_.size(), 0);
    
    for (size_t i = 0; i < digits_.size(); i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < other.digits_.size(); j++) {
            uint64_t product = static_cast<uint64_t>(digits_[i]) * other.digits_[j] + 
                              result.digits_[i + j] + carry;
            result.digits_[i + j] = static_cast<uint32_t>(product & 0xFFFFFFFF);
            carry = product >> 32;
        }
        if (carry) {
            result.digits_[i + other.digits_.size()] += static_cast<uint32_t>(carry);
        }
    }
    
    result.normalize();
    return result;
}

inline BigInteger BigInteger::operator/(const BigInteger& other) const {
    if (other.is_zero()) {
        throw std::runtime_error("Division by zero");
    }
    
    BigInteger quotient, remainder;
    divide(*this, other, quotient, remainder);
    return quotient;
}

inline BigInteger BigInteger::operator%(const BigInteger& other) const {
    if (other.is_zero()) {
        throw std::runtime_error("Division by zero");
    }
    
    BigInteger quotient, remainder;
    divide(*this, other, quotient, remainder);
    return remainder;
}

inline bool BigInteger::operator==(const BigInteger& other) const {
    return negative_ == other.negative_ && digits_ == other.digits_;
}

inline bool BigInteger::operator!=(const BigInteger& other) const {
    return !(*this == other);
}

inline bool BigInteger::operator<(const BigInteger& other) const {
    if (negative_ != other.negative_) {
        return negative_;
    }
    
    int cmp = compare_abs(other);
    return negative_ ? (cmp > 0) : (cmp < 0);
}

inline BigInteger BigInteger::mod_pow(const BigInteger& exponent, const BigInteger& modulus) const {
    if (modulus.is_zero()) {
        throw std::runtime_error("Modulus cannot be zero");
    }
    
    BigInteger result(1);
    BigInteger base = *this % modulus;
    BigInteger exp = exponent;
    
    while (!exp.is_zero()) {
        if (exp.is_odd()) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp = exp >> 1;
    }
    
    return result;
}

inline BigInteger BigInteger::mod_inverse(const BigInteger& modulus) const {
    BigInteger a = *this, b = modulus;
    BigInteger x(1), y(0), u(0), v(1);
    
    while (!b.is_zero()) {
        BigInteger q = a / b;
        BigInteger temp = b;
        b = a % b;
        a = temp;
        
        temp = u;
        u = x - q * u;
        x = temp;
        
        temp = v;
        v = y - q * v;
        y = temp;
    }
    
    if (x < BigInteger(0)) {
        x = x + modulus;
    }
    
    return x;
}

inline BigInteger BigInteger::gcd(const BigInteger& other) const {
    BigInteger a = *this, b = other;
    
    while (!b.is_zero()) {
        BigInteger temp = b;
        b = a % b;
        a = temp;
    }
    
    return a;
}

inline bool BigInteger::is_zero() const {
    return digits_.size() == 1 && digits_[0] == 0;
}

inline bool BigInteger::is_odd() const {
    return !is_zero() && (digits_[0] & 1);
}

inline size_t BigInteger::bit_length() const {
    if (is_zero()) return 0;
    
    size_t bits = (digits_.size() - 1) * 32;
    uint32_t top = digits_.back();
    
    while (top > 0) {
        bits++;
        top >>= 1;
    }
    
    return bits;
}

inline std::vector<uint8_t> BigInteger::to_bytes() const {
    if (is_zero()) return {0};
    
    std::vector<uint8_t> result;
    for (int i = digits_.size() - 1; i >= 0; i--) {
        uint32_t digit = digits_[i];
        for (int j = 3; j >= 0; j--) {
            uint8_t byte = static_cast<uint8_t>((digit >> (j * 8)) & 0xFF);
            if (!result.empty() || byte != 0) {
                result.push_back(byte);
            }
        }
    }
    
    return result.empty() ? std::vector<uint8_t>{0} : result;
}

inline std::string BigInteger::to_string() const {
    if (is_zero()) return "0";
    
    std::stringstream ss;
    if (negative_) ss << "-";
    
    for (int i = digits_.size() - 1; i >= 0; i--) {
        if (i == static_cast<int>(digits_.size()) - 1) {
            ss << std::hex << digits_[i];
        } else {
            ss << std::setfill('0') << std::setw(8) << std::hex << digits_[i];
        }
    }
    
    return ss.str();
}

inline BigInteger BigInteger::generate_prime(size_t bit_length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    BigInteger candidate;
    do {
        std::vector<uint8_t> bytes((bit_length + 7) / 8);
        for (auto& byte : bytes) {
            byte = dis(gen);
        }
        
        // Set high bit and make odd
        bytes[0] |= 0x80;
        bytes[bytes.size() - 1] |= 0x01;
        
        candidate = BigInteger(bytes);
    } while (!candidate.is_prime());
    
    return candidate;
}

inline bool BigInteger::is_prime() const {
    if (*this < BigInteger(2)) return false;
    if (*this == BigInteger(2) || *this == BigInteger(3)) return true;
    if (!is_odd()) return false;
    
    // Miller-Rabin primality test
    BigInteger n_minus_1 = *this - BigInteger(1);
    BigInteger d = n_minus_1;
    int r = 0;
    
    while (!d.is_odd()) {
        d = d >> 1;
        r++;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Test with k=10 rounds
    for (int k = 0; k < 10; k++) {
        BigInteger a(2 + (gen() % (bit_length() - 4)));
        BigInteger x = a.mod_pow(d, *this);
        
        if (x == BigInteger(1) || x == n_minus_1) continue;
        
        bool composite = true;
        for (int i = 0; i < r - 1; i++) {
            x = x.mod_pow(BigInteger(2), *this);
            if (x == n_minus_1) {
                composite = false;
                break;
            }
        }
        
        if (composite) return false;
    }
    
    return true;
}

inline void BigInteger::normalize() {
    while (digits_.size() > 1 && digits_.back() == 0) {
        digits_.pop_back();
    }
    if (digits_.empty()) {
        digits_ = {0};
        negative_ = false;
    } else if (is_zero()) {
        negative_ = false;
    }
}

inline int BigInteger::compare_abs(const BigInteger& other) const {
    if (digits_.size() != other.digits_.size()) {
        return (digits_.size() < other.digits_.size()) ? -1 : 1;
    }
    
    for (int i = digits_.size() - 1; i >= 0; i--) {
        if (digits_[i] < other.digits_[i]) return -1;
        if (digits_[i] > other.digits_[i]) return 1;
    }
    return 0;
}

inline void BigInteger::divide(const BigInteger& dividend, const BigInteger& divisor,
                             BigInteger& quotient, BigInteger& remainder) {
    quotient = BigInteger(0);
    remainder = dividend;
    
    if (divisor.is_zero()) {
        throw std::runtime_error("Division by zero");
    }
    
    if (dividend.compare_abs(divisor) < 0) {
        return;
    }
    
    int shift = dividend.bit_length() - divisor.bit_length();
    BigInteger shifted_divisor = divisor << shift;
    
    for (int i = shift; i >= 0; i--) {
        if (remainder.compare_abs(shifted_divisor) >= 0) {
            remainder = remainder - shifted_divisor;
            quotient = quotient + (BigInteger(1) << i);
        }
        shifted_divisor = shifted_divisor >> 1;
    }
}

inline BigInteger BigInteger::operator<<(int shift) const {
    if (shift == 0 || is_zero()) return *this;
    
    BigInteger result = *this;
    int word_shift = shift / 32;
    int bit_shift = shift % 32;
    
    if (word_shift > 0) {
        result.digits_.insert(result.digits_.begin(), word_shift, 0);
    }
    
    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (size_t i = word_shift; i < result.digits_.size(); i++) {
            uint64_t temp = (static_cast<uint64_t>(result.digits_[i]) << bit_shift) | carry;
            result.digits_[i] = static_cast<uint32_t>(temp & 0xFFFFFFFF);
            carry = static_cast<uint32_t>(temp >> 32);
        }
        if (carry) {
            result.digits_.push_back(carry);
        }
    }
    
    return result;
}

inline BigInteger BigInteger::operator>>(int shift) const {
    if (shift == 0 || is_zero()) return *this;
    
    BigInteger result = *this;
    int word_shift = shift / 32;
    int bit_shift = shift % 32;
    
    if (word_shift >= static_cast<int>(result.digits_.size())) {
        return BigInteger(0);
    }
    
    if (word_shift > 0) {
        result.digits_.erase(result.digits_.begin(), result.digits_.begin() + word_shift);
    }
    
    if (bit_shift > 0 && !result.digits_.empty()) {
        uint32_t carry = 0;
        for (int i = result.digits_.size() - 1; i >= 0; i--) {
            uint32_t temp = result.digits_[i];
            result.digits_[i] = (temp >> bit_shift) | (carry << (32 - bit_shift));
            carry = temp & ((1U << bit_shift) - 1);
        }
    }
    
    result.normalize();
    return result;
}

// RSAImpl inline implementations

inline std::vector<uint8_t> RSAImpl::pkcs1_pad_encryption(const std::vector<uint8_t>& data, 
                                                         size_t key_size) const {
    size_t max_data_len = key_size - 11; // PKCS#1 v1.5 padding overhead
    if (data.size() > max_data_len) {
        throw std::runtime_error("Data too large for RSA encryption");
    }
    
    std::vector<uint8_t> padded(key_size);
    padded[0] = 0x00;
    padded[1] = 0x02;
    
    // Fill with random non-zero bytes
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(1, 255);
    
    size_t padding_len = key_size - data.size() - 3;
    for (size_t i = 2; i < 2 + padding_len; i++) {
        padded[i] = dis(gen);
    }
    
    padded[2 + padding_len] = 0x00;
    std::copy(data.begin(), data.end(), padded.begin() + 3 + padding_len);
    
    return padded;
}

inline std::vector<uint8_t> RSAImpl::pkcs1_unpad_encryption(const std::vector<uint8_t>& data) const {
    if (data.size() < 11 || data[0] != 0x00 || data[1] != 0x02) {
        throw std::runtime_error("Invalid PKCS#1 padding");
    }
    
    size_t separator_pos = 0;
    for (size_t i = 2; i < data.size(); i++) {
        if (data[i] == 0x00) {
            separator_pos = i;
            break;
        }
    }
    
    if (separator_pos == 0 || separator_pos < 10) {
        throw std::runtime_error("Invalid PKCS#1 padding");
    }
    
    return std::vector<uint8_t>(data.begin() + separator_pos + 1, data.end());
}

inline RSAKeyPair RSAImpl::generate_keypair(size_t key_size) {
    if (key_size < 1024 || key_size % 8 != 0) {
        throw std::runtime_error("Invalid key size");
    }
    
    size_t prime_bits = key_size / 2;
    
    BigInteger p, q, n, phi, e(65537), d;
    
    do {
        p = BigInteger::generate_prime(prime_bits);
        q = BigInteger::generate_prime(prime_bits);
        n = p * q;
    } while (n.bit_length() != key_size);
    
    phi = (p - BigInteger(1)) * (q - BigInteger(1));
    
    // Ensure e and phi are coprime
    while (e.gcd(phi) != BigInteger(1)) {
        e = e + BigInteger(2);
    }
    
    d = e.mod_inverse(phi);
    
    RSAPublicKey public_key{n, e};
    RSAPrivateKey private_key{n, d, p, q};
    
    return RSAKeyPair{public_key, private_key};
}

inline std::vector<uint8_t> RSAImpl::encrypt(const std::vector<uint8_t>& plaintext,
                                            const RSAPublicKey& public_key) {
    size_t key_bytes = (public_key.n.bit_length() + 7) / 8;
    auto padded = pkcs1_pad_encryption(plaintext, key_bytes);
    
    BigInteger m(padded);
    BigInteger c = m.mod_pow(public_key.e, public_key.n);
    
    auto result = c.to_bytes();
    
    // Ensure result is key_bytes long
    if (result.size() < key_bytes) {
        result.insert(result.begin(), key_bytes - result.size(), 0);
    }
    
    return result;
}

inline std::vector<uint8_t> RSAImpl::decrypt(const std::vector<uint8_t>& ciphertext,
                                            const RSAPrivateKey& private_key) {
    BigInteger c(ciphertext);
    BigInteger m = c.mod_pow(private_key.d, private_key.n);
    
    auto padded = m.to_bytes();
    size_t key_bytes = (private_key.n.bit_length() + 7) / 8;
    
    // Ensure padded is key_bytes long
    if (padded.size() < key_bytes) {
        padded.insert(padded.begin(), key_bytes - padded.size(), 0);
    }
    
    return pkcs1_unpad_encryption(padded);
}

inline std::vector<uint8_t> RSAImpl::sign(const std::vector<uint8_t>& hash,
                                         const std::string& hash_algorithm,
                                         const RSAPrivateKey& private_key) {
    size_t key_bytes = (private_key.n.bit_length() + 7) / 8;
    auto padded = pkcs1_pad_signature(hash, hash_algorithm, key_bytes);
    
    BigInteger m(padded);
    BigInteger s = m.mod_pow(private_key.d, private_key.n);
    
    auto result = s.to_bytes();
    
    // Ensure result is key_bytes long
    if (result.size() < key_bytes) {
        result.insert(result.begin(), key_bytes - result.size(), 0);
    }
    
    return result;
}

inline bool RSAImpl::verify(const std::vector<uint8_t>& hash,
                           const std::vector<uint8_t>& signature,
                           const std::string& hash_algorithm,
                           const RSAPublicKey& public_key) {
    try {
        BigInteger s(signature);
        BigInteger m = s.mod_pow(public_key.e, public_key.n);
        
        auto padded = m.to_bytes();
        size_t key_bytes = (public_key.n.bit_length() + 7) / 8;
        
        // Ensure padded is key_bytes long
        if (padded.size() < key_bytes) {
            padded.insert(padded.begin(), key_bytes - padded.size(), 0);
        }
        
        auto expected_padded = pkcs1_pad_signature(hash, hash_algorithm, key_bytes);
        return padded == expected_padded;
    } catch (...) {
        return false;
    }
}

} // namespace crypto
} // namespace lockey
