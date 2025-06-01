#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <random>
#include <limits>
#include <algorithm>

namespace lockey {

class BigInt {
public:
    BigInt(uint64_t v = 0) {
        limbs.clear();
        if (v == 0) return;
        limbs.push_back(static_cast<uint32_t>(v & 0xFFFFFFFFu));
        uint32_t hi = static_cast<uint32_t>(v >> 32);
        if (hi) limbs.push_back(hi);
    }

    BigInt(const std::string &s) {
        limbs.clear();
        BigInt ten(10);
        BigInt result(0);
        for (char c : s) {
            if (c < '0' || c > '9') continue;
            result = result * ten + BigInt(static_cast<uint64_t>(c - '0'));
        }
        limbs = result.limbs;
    }

    BigInt(const std::vector<uint8_t> &bytes) {
        BigInt result(0);
        BigInt base(256);
        for (uint8_t b : bytes) {
            result = (result * base) + BigInt(static_cast<uint64_t>(b));
        }
        limbs = result.limbs;
    }

    bool isZero() const {
        return limbs.empty();
    }

    std::string toString() const {
        if (isZero()) return "0";
        BigInt tmp = *this;
        BigInt ten(10);
        std::string s;
        while (!tmp.isZero()) {
            auto dm = divMod(tmp, ten);
            uint32_t d = dm.second.limbs.empty() ? 0 : dm.second.limbs[0];
            s.push_back(static_cast<char>('0' + d));
            tmp = dm.first;
        }
        std::reverse(s.begin(), s.end());
        return s;
    }

    static BigInt randomBits(size_t bitCount) {
        size_t limbCount = (bitCount + 31) / 32;
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, std::numeric_limits<uint32_t>::max());
        BigInt r;
        r.limbs.resize(limbCount);
        for (size_t i = 0; i < limbCount; ++i) {
            r.limbs[i] = dist(gen);
        }
        int topBits = static_cast<int>(bitCount % 32);
        if (topBits == 0) topBits = 32;
        uint32_t mask = (topBits == 32 ? 0xFFFFFFFFu : ((1u << topBits) - 1));
        r.limbs.back() &= mask;
        r.limbs.back() |= (1u << (topBits - 1));
        r.limbs[0] |= 1;
        trim(r);
        return r;
    }

    static BigInt randomRange(const BigInt &min, const BigInt &max) {
        if (min >= max) return min;
        BigInt range = max - min;
        size_t bits = range.bitLength();
        BigInt result;
        do {
            result = randomBits(bits);
        } while (result > range);
        return result + min;
    }

    int bitLength() const {
        if (limbs.empty()) return 0;
        uint32_t top = limbs.back();
        int bits = 32 * (static_cast<int>(limbs.size()) - 1);
        bits += 32 - __builtin_clz(top);
        return bits;
    }

    bool operator<(const BigInt &other) const {
        return compare(*this, other) < 0;
    }

    bool operator>(const BigInt &other) const {
        return compare(*this, other) > 0;
    }

    bool operator<=(const BigInt &other) const {
        return compare(*this, other) <= 0;
    }

    bool operator>=(const BigInt &other) const {
        return compare(*this, other) >= 0;
    }

    bool operator==(const BigInt &other) const {
        return compare(*this, other) == 0;
    }

    bool operator!=(const BigInt &other) const {
        return compare(*this, other) != 0;
    }

    BigInt operator+(const BigInt &other) const {
        BigInt a = *this;
        BigInt b = other;
        size_t n = std::max(a.limbs.size(), b.limbs.size());
        a.limbs.resize(n);
        b.limbs.resize(n);
        uint64_t carry = 0;
        for (size_t i = 0; i < n; ++i) {
            uint64_t sum = static_cast<uint64_t>(a.limbs[i]) + b.limbs[i] + carry;
            a.limbs[i] = static_cast<uint32_t>(sum & 0xFFFFFFFFu);
            carry = sum >> 32;
        }
        if (carry) a.limbs.push_back(static_cast<uint32_t>(carry));
        trim(a);
        return a;
    }

    BigInt operator-(const BigInt &other) const {
        BigInt a = *this;
        BigInt b = other;
        a.limbs.resize(std::max(a.limbs.size(), b.limbs.size()));
        b.limbs.resize(a.limbs.size());
        int64_t carry = 0;
        for (size_t i = 0; i < a.limbs.size(); ++i) {
            int64_t diff = static_cast<int64_t>(a.limbs[i]) - b.limbs[i] + carry;
            if (diff < 0) {
                diff += (1LL << 32);
                carry = -1;
            } else {
                carry = 0;
            }
            a.limbs[i] = static_cast<uint32_t>(diff);
        }
        trim(a);
        return a;
    }

    BigInt operator*(const BigInt &other) const {
        if (isZero() || other.isZero()) return BigInt(0);
        BigInt r;
        size_t n = limbs.size();
        size_t m = other.limbs.size();
        r.limbs.assign(n + m, 0);
        for (size_t i = 0; i < n; ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < m || carry; ++j) {
                uint64_t cur = r.limbs[i + j] + carry;
                if (j < m) cur += static_cast<uint64_t>(limbs[i]) * other.limbs[j];
                r.limbs[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFFu);
                carry = cur >> 32;
            }
        }
        trim(r);
        return r;
    }

    BigInt operator/(const BigInt &other) const {
        return divMod(*this, other).first;
    }

    BigInt operator%(const BigInt &other) const {
        return divMod(*this, other).second;
    }

    BigInt operator<<(int bits) const {
        if (isZero()) return BigInt(0);
        int limbShift = bits / 32;
        int rem = bits % 32;
        BigInt r;
        r.limbs.assign(limbShift, 0);
        uint64_t carry = 0;
        for (size_t i = 0; i < limbs.size(); ++i) {
            uint64_t cur = (static_cast<uint64_t>(limbs[i]) << rem) | carry;
            r.limbs.push_back(static_cast<uint32_t>(cur & 0xFFFFFFFFu));
            carry = cur >> 32;
        }
        if (carry) r.limbs.push_back(static_cast<uint32_t>(carry));
        trim(r);
        return r;
    }

    BigInt operator>>(int bits) const {
        int limbShift = bits / 32;
        int rem = bits % 32;
        if (static_cast<int>(limbs.size()) <= limbShift) return BigInt(0);
        BigInt r;
        r.limbs.resize(limbs.size() - limbShift);
        uint64_t carry = 0;
        for (int i = static_cast<int>(limbs.size()) - 1; i >= limbShift; --i) {
            uint64_t cur = limbs[i];
            r.limbs[i - limbShift] = static_cast<uint32_t>((cur >> rem) | (carry << (32 - rem)));
            carry = cur & ((1ULL << rem) - 1);
        }
        trim(r);
        return r;
    }

    BigInt modExp(const BigInt &exp, const BigInt &mod) const {
        BigInt base = *this % mod;
        BigInt e = exp;
        BigInt result(1);
        while (!e.isZero()) {
            if (e.limbs[0] & 1) result = (result * base) % mod;
            base = (base * base) % mod;
            e = e >> 1;
        }
        return result;
    }

    static std::pair<BigInt, BigInt> divMod(const BigInt &a, const BigInt &b) {
        if (b.isZero()) return {BigInt(0), BigInt(0)};
        if (compare(a, b) < 0) return {BigInt(0), a};
        int shift = a.bitLength() - b.bitLength();
        BigInt bShift = b << shift;
        BigInt remainder = a;
        BigInt quotient(0);
        for (int i = shift; i >= 0; --i) {
            if (remainder >= bShift) {
                remainder = remainder - bShift;
                quotient = quotient + (BigInt(1) << i);
            }
            bShift = bShift >> 1;
        }
        trim(quotient);
        trim(remainder);
        return {quotient, remainder};
    }

    static int compare(const BigInt &a, const BigInt &b) {
        if (a.limbs.size() != b.limbs.size())
            return a.limbs.size() < b.limbs.size() ? -1 : 1;
        for (int i = static_cast<int>(a.limbs.size()) - 1; i >= 0; --i) {
            if (a.limbs[i] != b.limbs[i])
                return a.limbs[i] < b.limbs[i] ? -1 : 1;
        }
        return 0;
    }

private:
    std::vector<uint32_t> limbs;

    static void trim(BigInt &a) {
        while (!a.limbs.empty() && a.limbs.back() == 0) a.limbs.pop_back();
    }
};
}