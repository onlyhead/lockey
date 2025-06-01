#pragma once
#include <cstdint>
#include <cstring>

namespace lockey {

static const uint32_t blake2s_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 }
};

inline uint32_t rotr32(uint32_t w, unsigned c) {
    return (w >> c) | (w << (32 - c));
}

static void blake2s_compress(uint32_t h[8], const uint8_t block[64], uint64_t t, bool last) {
    uint32_t v[16];
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)block[4*i] |
               ((uint32_t)block[4*i+1] << 8) |
               ((uint32_t)block[4*i+2] << 16) |
               ((uint32_t)block[4*i+3] << 24);
    }
    for (int i = 0; i < 8; ++i) v[i] = h[i];
    for (int i = 0; i < 8; ++i) v[i+8] = blake2s_IV[i];
    v[12] ^= (uint32_t)t;
    v[13] ^= (uint32_t)(t >> 32);
    if (last) v[14] = ~v[14];
    #define B2S_G(a,b,c,d,x,y) \
        a = a + b + x; d = rotr32(d ^ a, 16); \
        c = c + d;     b = rotr32(b ^ c, 12); \
        a = a + b + y; d = rotr32(d ^ a, 8);  \
        c = c + d;     b = rotr32(b ^ c, 7);

    for (int r = 0; r < 10; ++r) {
        const uint8_t *s = blake2s_sigma[r];
        B2S_G(v[0], v[4], v[ 8], v[12], m[s[0]],  m[s[1]]);
        B2S_G(v[1], v[5], v[ 9], v[13], m[s[2]],  m[s[3]]);
        B2S_G(v[2], v[6], v[10], v[14], m[s[4]],  m[s[5]]);
        B2S_G(v[3], v[7], v[11], v[15], m[s[6]],  m[s[7]]);
        B2S_G(v[0], v[5], v[10], v[15], m[s[8]],  m[s[9]]);
        B2S_G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        B2S_G(v[2], v[7], v[ 8], v[13], m[s[12]], m[s[13]]);
        B2S_G(v[3], v[4], v[ 9], v[14], m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; ++i) {
        h[i] ^= v[i] ^ v[i+8];
    }
    #undef B2S_G
}

inline void blake2s(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint32_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = blake2s_IV[i];
    h[0] ^= 0x01010000 ^ 32;
    uint64_t t = 0;
    uint8_t buf[64];
    size_t offset = 0;
    while (inlen - offset > 64) {
        std::memcpy(buf, in + offset, 64);
        t += 64;
        blake2s_compress(h, buf, t, false);
        offset += 64;
    }
    size_t left = inlen - offset;
    std::memset(buf, 0, 64);
    std::memcpy(buf, in + offset, left);
    t += left;
    blake2s_compress(h, buf, t, true);
    for (int i = 0; i < 8; ++i) {
        uint32_t word = h[i];
        out[4*i + 0] = (uint8_t)word;
        out[4*i + 1] = (uint8_t)(word >> 8);
        out[4*i + 2] = (uint8_t)(word >> 16);
        out[4*i + 3] = (uint8_t)(word >> 24);
    }
}

}