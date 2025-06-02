#pragma once
#include "bigint.hpp"
#include "blake2s.hpp"
#include <random>
#include <vector>
#include <limits>

namespace lockey {

struct RSAKeyPair {
    Cypher n;
    Cypher e;
    Cypher d;
};

class RSA {
public:
    static RSAKeyPair generateKey(size_t bitLength) {
        Cypher one(1);
        Cypher eVal(65537);
        Cypher p = randomPrime(bitLength / 2);
        Cypher q = randomPrime(bitLength / 2);
        Cypher n = p * q;
        Cypher phi = (p - one) * (q - one);
        Cypher dVal = modInverse(eVal, phi);
        return RSAKeyPair{n, eVal, dVal};
    }

    static Cypher encrypt(const Cypher &m, const Cypher &e, const Cypher &n) {
        return m.modExp(e, n);
    }

    static Cypher decrypt(const Cypher &c, const Cypher &d, const Cypher &n) {
        return c.modExp(d, n);
    }

    static Cypher signRaw(const Cypher &m, const Cypher &d, const Cypher &n) {
        return m.modExp(d, n);
    }

    static bool verifyRaw(const Cypher &m, const Cypher &s, const Cypher &e, const Cypher &n) {
        Cypher m2 = s.modExp(e, n);
        return m2 == m;
    }

    static Cypher sign(const std::vector<uint8_t> &message, const Cypher &d, const Cypher &n) {
        uint8_t hash[32];
        blake2s(hash, message.data(), message.size());
        Cypher hBI(std::vector<uint8_t>(hash, hash + 32));
        return hBI.modExp(d, n);
    }

    static bool verify(const std::vector<uint8_t> &message, const Cypher &s, const Cypher &e, const Cypher &n) {
        uint8_t hash[32];
        blake2s(hash, message.data(), message.size());
        Cypher hBI(std::vector<uint8_t>(hash, hash + 32));
        Cypher m2 = s.modExp(e, n);
        return m2 == hBI;
    }

    // Utility functions made public
    static Cypher modInverse(const Cypher &a, const Cypher &m) {
        // Extended Euclidean Algorithm for unsigned Cypher
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
                // Handle potential negative case by finding equivalent positive value
                Cypher diff = quotient * s - old_s;
                Cypher cycles = (diff + m - Cypher(1)) / m;
                s = old_s + cycles * m - quotient * s;
            }
            old_s = temp;
        }
        
        if (old_r != Cypher(1)) {
            return Cypher(0); // No modular inverse exists
        }
        
        return old_s % m;
    }

private:
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

    static Cypher gcd(const Cypher &a, const Cypher &b) {
        if (b.isZero()) return a;
        return gcd(b, a % b);
    }

    static Cypher extendedGCD(const Cypher &a, const Cypher &b, Cypher &x, Cypher &y) {
        if (b.isZero()) {
            x = Cypher(1);
            y = Cypher(0);
            return a;
        }
        Cypher x1, y1;
        Cypher d = extendedGCD(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return d;
    }

    static Cypher randomPrime(size_t bitLength) {
        Cypher p;
        do {
            p = Cypher::randomBits(bitLength);
        } while (!isPrime(p));
        return p;
    }
};

} // namespace lockey
