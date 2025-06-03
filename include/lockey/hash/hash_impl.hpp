#pragma once

#include "hash_functions.hpp"

namespace lockey {
namespace hash {

// SHA-256 Implementation
inline void SHA256::update(const uint8_t* data, size_t length) {
    total_length_ += length;
    
    while (length > 0) {
        size_t space_in_buffer = BLOCK_SIZE - buffer_length_;
        size_t to_copy = (length < space_in_buffer) ? length : space_in_buffer;
        
        std::memcpy(buffer_.data() + buffer_length_, data, to_copy);
        buffer_length_ += to_copy;
        data += to_copy;
        length -= to_copy;
        
        if (buffer_length_ == BLOCK_SIZE) {
            process_block();
            buffer_length_ = 0;
        }
    }
}

inline void SHA256::finalize(uint8_t* output) {
    // Padding
    uint64_t bit_length = total_length_ * 8;
    uint8_t padding = 0x80;
    update(&padding, 1);
    
    // Pad to 56 bytes (448 bits) modulo 64
    while (buffer_length_ != 56) {
        padding = 0x00;
        update(&padding, 1);
    }
    
    // Append length in big-endian format
    for (int i = 7; i >= 0; --i) {
        uint8_t byte = (bit_length >> (i * 8)) & 0xFF;
        update(&byte, 1);
    }
    
    // Convert state to big-endian and copy to output
    for (int i = 0; i < 8; ++i) {
        for (int j = 3; j >= 0; --j) {
            output[i * 4 + (3 - j)] = (state_[i] >> (j * 8)) & 0xFF;
        }
    }
}

inline void SHA256::process_block() {
    std::array<uint32_t, 64> w;
    
    // Prepare message schedule
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(buffer_[i * 4]) << 24) |
               (static_cast<uint32_t>(buffer_[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(buffer_[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(buffer_[i * 4 + 3]);
    }
    
    for (int i = 16; i < 64; ++i) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }
    
    // Initialize working variables
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    
    // Main loop
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Add compressed chunk to current hash value
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

// SHA-384 Implementation
inline void SHA384::update(const uint8_t* data, size_t length) {
    total_length_ += length;
    
    while (length > 0) {
        size_t space_in_buffer = BLOCK_SIZE - buffer_length_;
        size_t to_copy = (length < space_in_buffer) ? length : space_in_buffer;
        
        std::memcpy(buffer_.data() + buffer_length_, data, to_copy);
        buffer_length_ += to_copy;
        data += to_copy;
        length -= to_copy;
        
        if (buffer_length_ == BLOCK_SIZE) {
            process_block();
            buffer_length_ = 0;
        }
    }
}

inline void SHA384::finalize(uint8_t* output) {
    // Padding
    uint64_t bit_length = total_length_ * 8;
    uint8_t padding = 0x80;
    update(&padding, 1);
    
    // Pad to 112 bytes (896 bits) modulo 128
    while (buffer_length_ != 112) {
        padding = 0x00;
        update(&padding, 1);
    }
    
    // Append length in big-endian format (128-bit)
    for (int i = 15; i >= 8; --i) {
        uint8_t byte = 0; // High 64 bits are zero
        update(&byte, 1);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t byte = (bit_length >> (i * 8)) & 0xFF;
        update(&byte, 1);
    }
    
    // Convert first 6 state words to big-endian and copy to output (384 bits)
    for (int i = 0; i < 6; ++i) {
        for (int j = 7; j >= 0; --j) {
            output[i * 8 + (7 - j)] = (state_[i] >> (j * 8)) & 0xFF;
        }
    }
}

inline void SHA384::process_block() {
    std::array<uint64_t, 80> w;
    
    // Prepare message schedule
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int j = 0; j < 8; ++j) {
            w[i] = (w[i] << 8) | buffer_[i * 8 + j];
        }
    }
    
    for (int i = 16; i < 80; ++i) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }
    
    // Initialize working variables
    uint64_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint64_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    
    // Main loop
    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint64_t t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Add compressed chunk to current hash value
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

// SHA-512 Implementation
inline void SHA512::update(const uint8_t* data, size_t length) {
    total_length_ += length;
    
    while (length > 0) {
        size_t space_in_buffer = BLOCK_SIZE - buffer_length_;
        size_t to_copy = (length < space_in_buffer) ? length : space_in_buffer;
        
        std::memcpy(buffer_.data() + buffer_length_, data, to_copy);
        buffer_length_ += to_copy;
        data += to_copy;
        length -= to_copy;
        
        if (buffer_length_ == BLOCK_SIZE) {
            process_block();
            buffer_length_ = 0;
        }
    }
}

inline void SHA512::finalize(uint8_t* output) {
    // Padding
    uint64_t bit_length = total_length_ * 8;
    uint8_t padding = 0x80;
    update(&padding, 1);
    
    // Pad to 112 bytes (896 bits) modulo 128
    while (buffer_length_ != 112) {
        padding = 0x00;
        update(&padding, 1);
    }
    
    // Append length in big-endian format (128-bit)
    for (int i = 15; i >= 8; --i) {
        uint8_t byte = 0; // High 64 bits are zero
        update(&byte, 1);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t byte = (bit_length >> (i * 8)) & 0xFF;
        update(&byte, 1);
    }
    
    // Convert state to big-endian and copy to output
    for (int i = 0; i < 8; ++i) {
        for (int j = 7; j >= 0; --j) {
            output[i * 8 + (7 - j)] = (state_[i] >> (j * 8)) & 0xFF;
        }
    }
}

inline void SHA512::process_block() {
    std::array<uint64_t, 80> w;
    
    // Prepare message schedule
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int j = 0; j < 8; ++j) {
            w[i] = (w[i] << 8) | buffer_[i * 8 + j];
        }
    }
    
    for (int i = 16; i < 80; ++i) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }
    
    // Initialize working variables
    uint64_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint64_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    
    // Main loop
    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint64_t t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Add compressed chunk to current hash value
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

} // namespace hash
} // namespace lockey
