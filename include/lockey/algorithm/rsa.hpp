#pragma once
#include "bigint.hpp"
#include "blake2s.hpp"
#include <random>
#include <vector>
#include <limits>

namespace lockey {

struct RSAKeyPair {
    BigInt n;
    BigInt e;
    BigInt d;
};

class RSA {
public:
    static RSAKeyPair generateKey(size_t bitLength) {
        BigInt one(1);
        BigInt eVal(65537);
        BigInt p = randomPrime(bitLength / 2);
        BigInt q = randomPrime(bitLength / 2);
        BigInt n = p * q;
        BigInt phi = (p - one) * (q - one);
        BigInt dVal = modInverse(eVal, phi);
        return RSAKeyPair{n, eVal, dVal};
    }

    static BigInt encrypt(const BigInt &m, const BigInt &e, const BigInt &n) {
        return m.modExp(e, n);
    }

    static BigInt decrypt(const BigInt &c, const BigInt &d, const BigInt &n) {
        return c.modExp(d, n);
    }

    static BigInt signRaw(const BigInt &m, const BigInt &d, const BigInt &n) {
        return m.modExp(d, n);
    }

    static bool verifyRaw(const BigInt &m, const BigInt &s, const BigInt &e, const BigInt &n) {
        BigInt m2 = s.modExp(e, n);
        return m2 == m;
    }

    static BigInt sign(const std::vector<uint8_t> &message, const BigInt &d, const BigInt &n) {
        uint8_t hash[32];
        blake2s(hash, message.data(), message.size());
        BigInt hBI(std::vector<uint8_t>(hash, hash + 32));
        return hBI.modExp(d, n);
    }

    static bool verify(const std::vector<uint8_t> &message, const BigInt &s, const BigInt &e, const BigInt &n) {
        uint8_t hash[32];
        blake2s(hash, message.data(), message.size());
        BigInt hBI(std::vector<uint8_t>(hash, hash + 32));
        BigInt m2 = s.modExp(e, n);
        return m2 == hBI;
    }

private:
    static bool isPrime(const BigInt &n, int iterations = 5) {
        if (n == BigInt(2) || n == BigInt(3)) return true;
        if (n.isZero()) return false;
        if (n.limbs.size() == 1 && (n.limbs[0] & 1) == 0) return false;
        BigInt d = n - BigInt(1);
        int r = 0;
        while ((d.limbs[0] & 1) == 0) {
            d = d >> 1;
            ++r;
        }
        std::random_device rd;
        std::mt19937_64 gen(rd());
        for (int i = 0; i < iterations; ++i) {
            BigInt a = BigInt::randomRange(BigInt(2), n - BigInt(2));
            if (!millerRabin(n, a, d, r)) return false;
        }
        return true;
    }

    static bool millerRabin(const BigInt &n, const BigInt &a, const BigInt &d, int r) {
        BigInt x = a.modExp(d, n);
        if (x == BigInt(1) || x == n - BigInt(1)) return true;
        BigInt temp = x;
        for (int i = 1; i < r; ++i) {
            temp = (temp * temp) % n;
            if (temp == n - BigInt(1)) return true;
        }
        return false;
    }

    static BigInt gcd(const BigInt &a, const BigInt &b) {
        if (b.isZero()) return a;
        return gcd(b, a % b);
    }

    static BigInt extendedGCD(const BigInt &a, const BigInt &b, BigInt &x, BigInt &y) {
        if (b.isZero()) {
            x = BigInt(1);
            y = BigInt(0);
            return a;
        }
        BigInt x1, y1;
        BigInt d = extendedGCD(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return d;
    }

    static BigInt modInverse(const BigInt &a, const BigInt &m) {
        BigInt x, y;
        BigInt g = extendedGCD(a, m, x, y);
        if (g != BigInt(1)) return BigInt(0);
        BigInt res = x % m;
        if (res < BigInt(0)) res = res + m;
        return res;
    }

    static BigInt randomPrime(size_t bitLength) {
        BigInt p;
        do {
            p = BigInt::randomBits(bitLength);
        } while (!isPrime(p));
        return p;
    }
};

} // namespace lockey
