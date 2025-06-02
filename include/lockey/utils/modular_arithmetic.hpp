#pragma once

#include "../algorithm/cypher.hpp"
#include <vector>
#include <cstdint>

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
    static Cypher mod_add(const Cypher& a, const Cypher& b, const Cypher& p);
    
    /**
     * @brief Subtract two numbers modulo p: (a - b) mod p
     */
    static Cypher mod_sub(const Cypher& a, const Cypher& b, const Cypher& p);
    
    /**
     * @brief Multiply two numbers modulo p: (a * b) mod p
     */
    static Cypher mod_mul(const Cypher& a, const Cypher& b, const Cypher& p);
    
    /**
     * @brief Square a number modulo p: (a * a) mod p
     */
    static Cypher mod_square(const Cypher& a, const Cypher& p);
    
    /**
     * @brief Calculate modular inverse: a^(-1) mod p
     * Uses extended Euclidean algorithm
     */
    static Cypher mod_inverse(const Cypher& a, const Cypher& p);
    
    /**
     * @brief Calculate modular division: (a / b) mod p = (a * b^(-1)) mod p
     */
    static Cypher mod_div(const Cypher& a, const Cypher& b, const Cypher& p);
    
    /**
     * @brief Calculate modular exponentiation: a^exp mod p
     * Uses binary exponentiation for efficiency
     */
    static Cypher mod_pow(const Cypher& base, const Cypher& exp, const Cypher& p);
    
    /**
     * @brief Calculate square root modulo p (for prime p ≡ 3 mod 4)
     * Returns one of the two square roots if it exists
     */
    static Cypher mod_sqrt(const Cypher& a, const Cypher& p);
    
    /**
     * @brief Check if a number is a quadratic residue modulo p
     * Uses Legendre symbol for prime modulus
     */
    static bool is_quadratic_residue(const Cypher& a, const Cypher& p);
    
private:
    /**
     * @brief Extended Euclidean algorithm
     * Returns gcd(a, b) and coefficients x, y such that ax + by = gcd(a, b)
     */
    static std::tuple<Cypher, Cypher, Cypher> extended_gcd(const Cypher& a, const Cypher& b);
    
    /**
     * @brief Compare two Cypher values: returns -1 if a < b, 0 if a == b, 1 if a > b
     */
    static int compare(const Cypher& a, const Cypher& b);
    
    /**
     * @brief Basic big integer addition without modular reduction
     */
    static Cypher big_add(const Cypher& a, const Cypher& b);
    
    /**
     * @brief Basic big integer subtraction (assumes a >= b)
     */
    static Cypher big_sub(const Cypher& a, const Cypher& b);
    
    /**
     * @brief Basic big integer multiplication
     */
    static Cypher big_mul(const Cypher& a, const Cypher& b);
    
    /**
     * @brief Basic big integer division, returns quotient and remainder
     */
    static std::pair<Cypher, Cypher> big_div(const Cypher& dividend, const Cypher& divisor);
    
    /**
     * @brief Reduce a big integer modulo p
     */
    static Cypher reduce_mod(const Cypher& a, const Cypher& p);
};

} // namespace utils
} // namespace lockey
