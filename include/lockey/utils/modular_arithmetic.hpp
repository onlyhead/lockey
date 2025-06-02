#pragma once

#include "../algorithm/cypher.hpp"
#include <vector>
#include <cstdint>
#include <algorithm>

namespace lockey {
namespace utils {

/**
 * @brief Utilities for modular arithmetic operations on big integers
 * 
 * This class provides essential modular arithmetic operations needed for
 * elliptic curve cryptography, including modular addition, subtraction,
 * multiplication, division, and inversion.
 */
class ModularArithmetic {
public:
    /**
     * @brief Add two numbers modulo p: (a + b) mod p
     */
    static Cypher mod_add(const Cypher& a, const Cypher& b, const Cypher& p) {
        // Convert to big integer representation for calculation
        auto a_bytes = a.toBytes();
        auto b_bytes = b.toBytes();
        auto p_bytes = p.toBytes();
        
        // Ensure same size by padding with zeros
        size_t max_size = std::max({a_bytes.size(), b_bytes.size(), p_bytes.size()});
        pad_to_size(a_bytes, max_size);
        pad_to_size(b_bytes, max_size);
        pad_to_size(p_bytes, max_size);
        
        std::vector<uint8_t> result = big_add(a_bytes, b_bytes);
        
        // Reduce modulo p
        if (big_compare(result, p_bytes) >= 0) {
            result = big_subtract(result, p_bytes);
        }
        
        return Cypher(result);
    }
    
    /**
     * @brief Subtract two numbers modulo p: (a - b) mod p
     */
    static Cypher mod_sub(const Cypher& a, const Cypher& b, const Cypher& p) {
        auto a_bytes = a.toBytes();
        auto b_bytes = b.toBytes();
        auto p_bytes = p.toBytes();
        
        size_t max_size = std::max({a_bytes.size(), b_bytes.size(), p_bytes.size()});
        pad_to_size(a_bytes, max_size);
        pad_to_size(b_bytes, max_size);
        pad_to_size(p_bytes, max_size);
        
        std::vector<uint8_t> result;
        
        if (big_compare(a_bytes, b_bytes) >= 0) {
            result = big_subtract(a_bytes, b_bytes);
        } else {
            // a < b, so compute (p - (b - a))
            auto temp = big_subtract(b_bytes, a_bytes);
            result = big_subtract(p_bytes, temp);
        }
        
        return Cypher(result);
    }
    
    /**
     * @brief Multiply two numbers modulo p: (a * b) mod p
     */
    static Cypher mod_mul(const Cypher& a, const Cypher& b, const Cypher& p) {
        auto result = big_multiply(a.toBytes(), b.toBytes());
        return Cypher(big_mod(result, p.toBytes()));
    }
    
    /**
     * @brief Square a number modulo p: (a * a) mod p
     */
    static Cypher mod_square(const Cypher& a, const Cypher& p) {
        return mod_mul(a, a, p);
    }
    
    /**
     * @brief Calculate modular inverse: a^(-1) mod p
     * Uses extended Euclidean algorithm
     */
    static Cypher mod_inverse(const Cypher& a, const Cypher& p) {
        auto a_bytes = a.toBytes();
        auto p_bytes = p.toBytes();
        
        // Extended Euclidean algorithm
        std::vector<uint8_t> old_r = p_bytes;
        std::vector<uint8_t> r = a_bytes;
        std::vector<uint8_t> old_s = {0};
        std::vector<uint8_t> s = {1};
        
        while (!is_zero(r)) {
            auto quotient = big_divide(old_r, r);
            
            auto new_r = big_subtract(old_r, big_multiply(quotient, r));
            old_r = r;
            r = new_r;
            
            auto temp = big_multiply(quotient, s);
            auto new_s = (big_compare(old_s, temp) >= 0) ? 
                         big_subtract(old_s, temp) : 
                         big_subtract(p_bytes, big_subtract(temp, old_s));
            old_s = s;
            s = new_s;
        }
        
        return Cypher(old_s);
    }
    
    /**
     * @brief Calculate modular division: (a / b) mod p = (a * b^(-1)) mod p
     */
    static Cypher mod_div(const Cypher& a, const Cypher& b, const Cypher& p) {
        auto b_inv = mod_inverse(b, p);
        return mod_mul(a, b_inv, p);
    }
    
    /**
     * @brief Calculate modular exponentiation: a^exp mod p
     * Uses binary exponentiation (square-and-multiply)
     */
    static Cypher mod_pow(const Cypher& base, const Cypher& exp, const Cypher& p) {
        Cypher result(std::vector<uint8_t>{1});
        Cypher base_mod = mod_add(base, Cypher(std::vector<uint8_t>{0}), p); // Ensure base is reduced mod p
        auto exp_bytes = exp.toBytes();
        
        for (size_t i = 0; i < exp_bytes.size(); ++i) {
            uint8_t byte = exp_bytes[exp_bytes.size() - 1 - i];
            for (int bit = 0; bit < 8; ++bit) {
                if (byte & (1 << bit)) {
                    result = mod_mul(result, base_mod, p);
                }
                base_mod = mod_square(base_mod, p);
            }
        }
        
        return result;
    }
    
    /**
     * @brief Check if a number is zero
     */
    static bool is_zero(const std::vector<uint8_t>& num) {
        return std::all_of(num.begin(), num.end(), [](uint8_t b) { return b == 0; });
    }
    
private:
    /**
     * @brief Pad vector to specified size with leading zeros
     */
    static void pad_to_size(std::vector<uint8_t>& vec, size_t size) {
        if (vec.size() < size) {
            vec.insert(vec.begin(), size - vec.size(), 0);
        }
    }
    
    /**
     * @brief Add two big integers represented as byte arrays
     */
    static std::vector<uint8_t> big_add(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> result(std::max(a.size(), b.size()) + 1, 0);
        uint16_t carry = 0;
        
        int i = a.size() - 1;
        int j = b.size() - 1;
        int k = result.size() - 1;
        
        while (i >= 0 || j >= 0 || carry > 0) {
            uint16_t sum = carry;
            if (i >= 0) sum += a[i--];
            if (j >= 0) sum += b[j--];
            
            result[k--] = sum & 0xFF;
            carry = sum >> 8;
        }
        
        // Remove leading zeros
        while (result.size() > 1 && result[0] == 0) {
            result.erase(result.begin());
        }
        
        return result;
    }
    
    /**
     * @brief Subtract two big integers (assumes a >= b)
     */
    static std::vector<uint8_t> big_subtract(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> result = a;
        int borrow = 0;
        
        int i = result.size() - 1;
        int j = b.size() - 1;
        
        while (j >= 0 || borrow > 0) {
            int diff = result[i] - borrow;
            if (j >= 0) diff -= b[j--];
            
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            
            result[i--] = diff;
        }
        
        // Remove leading zeros
        while (result.size() > 1 && result[0] == 0) {
            result.erase(result.begin());
        }
        
        return result;
    }
    
    /**
     * @brief Multiply two big integers
     */
    static std::vector<uint8_t> big_multiply(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> result(a.size() + b.size(), 0);
        
        for (int i = a.size() - 1; i >= 0; --i) {
            uint16_t carry = 0;
            for (int j = b.size() - 1; j >= 0; --j) {
                uint32_t prod = static_cast<uint32_t>(a[i]) * b[j] + 
                               result[i + j + 1] + carry;
                result[i + j + 1] = prod & 0xFF;
                carry = prod >> 8;
            }
            result[i] += carry;
        }
        
        // Remove leading zeros
        while (result.size() > 1 && result[0] == 0) {
            result.erase(result.begin());
        }
        
        return result;
    }
    
    /**
     * @brief Compare two big integers
     * Returns: -1 if a < b, 0 if a == b, 1 if a > b
     */
    static int big_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() < b.size()) return -1;
        if (a.size() > b.size()) return 1;
        
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        
        return 0;
    }
    
    /**
     * @brief Divide two big integers, return quotient
     */
    static std::vector<uint8_t> big_divide(const std::vector<uint8_t>& dividend, const std::vector<uint8_t>& divisor) {
        if (big_compare(dividend, divisor) < 0) {
            return {0};
        }
        
        // Simple implementation - subtract divisor until remainder < divisor
        std::vector<uint8_t> quotient = {0};
        std::vector<uint8_t> remainder = dividend;
        
        while (big_compare(remainder, divisor) >= 0) {
            remainder = big_subtract(remainder, divisor);
            quotient = big_add(quotient, {1});
        }
        
        return quotient;
    }
    
    /**
     * @brief Modulo operation for big integers
     */
    static std::vector<uint8_t> big_mod(const std::vector<uint8_t>& dividend, const std::vector<uint8_t>& divisor) {
        if (big_compare(dividend, divisor) < 0) {
            return dividend;
        }
        
        std::vector<uint8_t> remainder = dividend;
        
        while (big_compare(remainder, divisor) >= 0) {
            remainder = big_subtract(remainder, divisor);
        }
        
        return remainder;
    }
};

} // namespace utils
} // namespace lockey
