#include "../include/lockey/utils/modular_arithmetic.hpp"
#include <algorithm>
#include <stdexcept>

namespace lockey {
namespace utils {

Cypher ModularArithmetic::mod_add(const Cypher& a, const Cypher& b, const Cypher& p) {
    Cypher sum = big_add(a, b);
    return reduce_mod(sum, p);
}

Cypher ModularArithmetic::mod_sub(const Cypher& a, const Cypher& b, const Cypher& p) {
    if (compare(a, b) >= 0) {
        return big_sub(a, b);
    } else {
        // a < b, so (a - b) mod p = (a + p - b) mod p
        Cypher sum = big_add(a, p);
        return big_sub(sum, b);
    }
}

Cypher ModularArithmetic::mod_mul(const Cypher& a, const Cypher& b, const Cypher& p) {
    Cypher product = big_mul(a, b);
    return reduce_mod(product, p);
}

Cypher ModularArithmetic::mod_square(const Cypher& a, const Cypher& p) {
    return mod_mul(a, a, p);
}

Cypher ModularArithmetic::mod_inverse(const Cypher& a, const Cypher& p) {
    auto [gcd, x, y] = extended_gcd(a, p);
    
    // Check if gcd(a, p) = 1 (a and p are coprime)
    Cypher one(std::vector<uint8_t>{1});
    if (!(gcd == one)) {
        throw std::runtime_error("Modular inverse does not exist");
    }
    
    // Ensure x is positive
    if (compare(x, Cypher(std::vector<uint8_t>{0})) < 0) {
        x = mod_add(x, p, p);
    }
    
    return x;
}

Cypher ModularArithmetic::mod_div(const Cypher& a, const Cypher& b, const Cypher& p) {
    Cypher b_inv = mod_inverse(b, p);
    return mod_mul(a, b_inv, p);
}

Cypher ModularArithmetic::mod_pow(const Cypher& base, const Cypher& exp, const Cypher& p) {
    Cypher result(std::vector<uint8_t>{1});
    Cypher base_mod = reduce_mod(base, p);
    Cypher exp_copy = exp;
    Cypher zero(std::vector<uint8_t>{0});
    Cypher one(std::vector<uint8_t>{1});
    Cypher two(std::vector<uint8_t>{2});
    
    while (!(exp_copy == zero)) {
        // If exp is odd, multiply result by base
        auto [quotient, remainder] = big_div(exp_copy, two);
        if (!(remainder == zero)) {
            result = mod_mul(result, base_mod, p);
        }
        
        // Square base and halve exponent
        base_mod = mod_square(base_mod, p);
        exp_copy = quotient;
    }
    
    return result;
}

Cypher ModularArithmetic::mod_sqrt(const Cypher& a, const Cypher& p) {
    // For primes p ≡ 3 (mod 4), we can use: sqrt(a) = a^((p+1)/4) mod p
    Cypher one(std::vector<uint8_t>{1});
    Cypher four(std::vector<uint8_t>{4});
    
    // Check if p ≡ 3 (mod 4)
    auto [q1, r1] = big_div(p, four);
    Cypher three(std::vector<uint8_t>{3});
    
    if (!(r1 == three)) {
        throw std::runtime_error("Square root algorithm only implemented for p ≡ 3 (mod 4)");
    }
    
    // Calculate (p + 1) / 4
    Cypher p_plus_one = big_add(p, one);
    auto [exp, remainder] = big_div(p_plus_one, four);
    
    // Calculate a^((p+1)/4) mod p
    return mod_pow(a, exp, p);
}

bool ModularArithmetic::is_quadratic_residue(const Cypher& a, const Cypher& p) {
    // Use Legendre symbol: a^((p-1)/2) mod p
    // Returns 1 if a is a quadratic residue, -1 (or p-1) if not, 0 if a ≡ 0 (mod p)
    Cypher one(std::vector<uint8_t>{1});
    Cypher two(std::vector<uint8_t>{2});
    
    Cypher p_minus_one = big_sub(p, one);
    auto [exp, remainder] = big_div(p_minus_one, two);
    
    Cypher legendre = mod_pow(a, exp, p);
    
    return legendre == one;
}

std::tuple<Cypher, Cypher, Cypher> ModularArithmetic::extended_gcd(const Cypher& a, const Cypher& b) {
    Cypher zero(std::vector<uint8_t>{0});
    Cypher one(std::vector<uint8_t>{1});
    
    if (b == zero) {
        return {a, one, zero};
    }
    
    auto [gcd, x1, y1] = extended_gcd(b, reduce_mod(a, b));
    
    // x = y1
    // y = x1 - (a/b) * y1
    auto [quotient, remainder] = big_div(a, b);
    Cypher y = big_sub(x1, big_mul(quotient, y1));
    
    return {gcd, y1, y};
}

int ModularArithmetic::compare(const Cypher& a, const Cypher& b) {
    auto a_bytes = a.toBytes();
    auto b_bytes = b.toBytes();
    
    // Remove leading zeros
    while (!a_bytes.empty() && a_bytes[0] == 0) a_bytes.erase(a_bytes.begin());
    while (!b_bytes.empty() && b_bytes[0] == 0) b_bytes.erase(b_bytes.begin());
    
    if (a_bytes.size() < b_bytes.size()) return -1;
    if (a_bytes.size() > b_bytes.size()) return 1;
    
    // Same length, compare byte by byte
    for (size_t i = 0; i < a_bytes.size(); ++i) {
        if (a_bytes[i] < b_bytes[i]) return -1;
        if (a_bytes[i] > b_bytes[i]) return 1;
    }
    
    return 0; // Equal
}

Cypher ModularArithmetic::big_add(const Cypher& a, const Cypher& b) {
    auto a_bytes = a.toBytes();
    auto b_bytes = b.toBytes();
    
    // Ensure a_bytes is the longer one
    if (a_bytes.size() < b_bytes.size()) {
        std::swap(a_bytes, b_bytes);
    }
    
    std::vector<uint8_t> result;
    uint16_t carry = 0;
    
    // Add from least significant byte
    for (int i = a_bytes.size() - 1; i >= 0; --i) {
        uint16_t sum = a_bytes[i] + carry;
        
        // Add corresponding byte from b if available
        int b_index = i - (a_bytes.size() - b_bytes.size());
        if (b_index >= 0) {
            sum += b_bytes[b_index];
        }
        
        result.insert(result.begin(), sum & 0xFF);
        carry = sum >> 8;
    }
    
    if (carry > 0) {
        result.insert(result.begin(), carry);
    }
    
    return Cypher(result);
}

Cypher ModularArithmetic::big_sub(const Cypher& a, const Cypher& b) {
    if (compare(a, b) < 0) {
        throw std::runtime_error("Cannot subtract larger number from smaller");
    }
    
    auto a_bytes = a.toBytes();
    auto b_bytes = b.toBytes();
    
    std::vector<uint8_t> result;
    int16_t borrow = 0;
    
    // Subtract from least significant byte
    for (int i = a_bytes.size() - 1; i >= 0; --i) {
        int16_t diff = a_bytes[i] - borrow;
        
        // Subtract corresponding byte from b if available
        int b_index = i - (a_bytes.size() - b_bytes.size());
        if (b_index >= 0) {
            diff -= b_bytes[b_index];
        }
        
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        
        result.insert(result.begin(), diff);
    }
    
    // Remove leading zeros
    while (!result.empty() && result[0] == 0) {
        result.erase(result.begin());
    }
    
    if (result.empty()) {
        result.push_back(0);
    }
    
    return Cypher(result);
}

Cypher ModularArithmetic::big_mul(const Cypher& a, const Cypher& b) {
    auto a_bytes = a.toBytes();
    auto b_bytes = b.toBytes();
    
    std::vector<uint32_t> result(a_bytes.size() + b_bytes.size(), 0);
    
    // Multiply each digit
    for (int i = a_bytes.size() - 1; i >= 0; --i) {
        for (int j = b_bytes.size() - 1; j >= 0; --j) {
            uint32_t product = a_bytes[i] * b_bytes[j];
            int pos = (a_bytes.size() - 1 - i) + (b_bytes.size() - 1 - j);
            
            result[pos] += product;
            
            // Handle carry
            if (result[pos] >= 256) {
                result[pos + 1] += result[pos] / 256;
                result[pos] %= 256;
            }
        }
    }
    
    // Convert back to bytes, removing leading zeros
    std::vector<uint8_t> final_result;
    bool leading_zero = true;
    
    for (int i = result.size() - 1; i >= 0; --i) {
        if (result[i] != 0 || !leading_zero) {
            final_result.push_back(result[i]);
            leading_zero = false;
        }
    }
    
    if (final_result.empty()) {
        final_result.push_back(0);
    }
    
    return Cypher(final_result);
}

std::pair<Cypher, Cypher> ModularArithmetic::big_div(const Cypher& dividend, const Cypher& divisor) {
    Cypher zero(std::vector<uint8_t>{0});
    
    if (divisor == zero) {
        throw std::runtime_error("Division by zero");
    }
    
    if (compare(dividend, divisor) < 0) {
        return {zero, dividend};
    }
    
    // Simple long division algorithm
    Cypher quotient = zero;
    Cypher remainder = dividend;
    Cypher one(std::vector<uint8_t>{1});
    
    while (compare(remainder, divisor) >= 0) {
        remainder = big_sub(remainder, divisor);
        quotient = big_add(quotient, one);
    }
    
    return {quotient, remainder};
}

Cypher ModularArithmetic::reduce_mod(const Cypher& a, const Cypher& p) {
    auto [quotient, remainder] = big_div(a, p);
    return remainder;
}

} // namespace utils
} // namespace lockey
