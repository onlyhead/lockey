#pragma once

#include "../utils/common.hpp"
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>

namespace lockey {
namespace utils {

/**
 * @brief Key file I/O operations
 */
class KeyIO {
public:
    // Simplified save/load methods for basic functionality
    static void save_key_to_file(const std::vector<uint8_t>& key_data, const std::string& filename);
    static std::vector<uint8_t> load_key_from_file(const std::string& filename);
    
    // Generic key save/load with metadata
    static void save_key_with_metadata(const std::string& filename,
                                     const std::vector<uint8_t>& key_data,
                                     const std::map<std::string, std::string>& metadata);
    static std::pair<std::vector<uint8_t>, std::map<std::string, std::string>> 
        load_key_with_metadata(const std::string& filename);
    
    // EC-specific key methods
    static void save_ec_private_key(const std::vector<uint8_t>& private_key, const std::string& filename);
    static void save_ec_public_key(const std::vector<uint8_t>& public_key, const std::string& filename);
    static std::vector<uint8_t> load_ec_private_key(const std::string& filename);
    static std::vector<uint8_t> load_ec_public_key(const std::string& filename);
    
    // RSA-specific key methods
    static void save_rsa_private_key(const std::vector<uint8_t>& private_key, const std::string& filename);
    static void save_rsa_public_key(const std::vector<uint8_t>& public_key, const std::string& filename);
    static std::vector<uint8_t> load_rsa_private_key(const std::string& filename);
    static std::vector<uint8_t> load_rsa_public_key(const std::string& filename);

private:
    // Base64 encoding/decoding for PEM format
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
};

// Inline implementations

inline void KeyIO::save_key_to_file(const std::vector<uint8_t>& key_data, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file for writing: " + filename);
    }
    file.write(reinterpret_cast<const char*>(key_data.data()), key_data.size());
}

inline std::vector<uint8_t> KeyIO::load_key_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return data;
}

inline void KeyIO::save_key_with_metadata(const std::string& filename,
                                        const std::vector<uint8_t>& key_data,
                                        const std::map<std::string, std::string>& metadata) {
    std::ofstream file(filename);
    if (!file) {
        throw std::runtime_error("Cannot open file for writing: " + filename);
    }
    
    // Write metadata as comments
    for (const auto& [key, value] : metadata) {
        file << "# " << key << ": " << value << "\n";
    }
    file << "# -----\n";
    
    // Write key data as base64
    auto base64_data = base64_encode(key_data);
    file << base64_data << "\n";
}

inline std::pair<std::vector<uint8_t>, std::map<std::string, std::string>> 
KeyIO::load_key_with_metadata(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }
    
    std::map<std::string, std::string> metadata;
    std::string line;
    std::string key_data_base64;
    
    bool in_metadata = true;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        if (line.find("# -----") == 0) {
            in_metadata = false;
            continue;
        }
        
        if (in_metadata && line.find("# ") == 0) {
            auto colon_pos = line.find(": ");
            if (colon_pos != std::string::npos) {
                std::string key = line.substr(2, colon_pos - 2);
                std::string value = line.substr(colon_pos + 2);
                metadata[key] = value;
            }
        } else if (!in_metadata) {
            key_data_base64 += line;
        }
    }
    
    auto key_data = base64_decode(key_data_base64);
    return {key_data, metadata};
}

inline std::string KeyIO::base64_encode(const std::vector<uint8_t>& data) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t value = data[i] << 16;
        if (i + 1 < data.size()) value |= data[i + 1] << 8;
        if (i + 2 < data.size()) value |= data[i + 2];
        
        result += chars[(value >> 18) & 0x3F];
        result += chars[(value >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? chars[(value >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? chars[value & 0x3F] : '=';
    }
    
    return result;
}

inline std::vector<uint8_t> KeyIO::base64_decode(const std::string& encoded) {
    static const std::array<int, 256> decode_table = []() {
        std::array<int, 256> table;
        table.fill(-1);
        for (int i = 0; i < 26; i++) {
            table['A' + i] = i;
            table['a' + i] = i + 26;
        }
        for (int i = 0; i < 10; i++) {
            table['0' + i] = i + 52;
        }
        table['+'] = 62;
        table['/'] = 63;
        return table;
    }();
    
    std::vector<uint8_t> result;
    uint32_t value = 0;
    int bits = 0;
    
    for (char c : encoded) {
        if (c == '=') break;
        if (decode_table[static_cast<unsigned char>(c)] == -1) continue;
        
        value = (value << 6) | decode_table[static_cast<unsigned char>(c)];
        bits += 6;
        
        if (bits >= 8) {
            result.push_back(static_cast<uint8_t>((value >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    
    return result;
}

// EC key method implementations
inline void KeyIO::save_ec_private_key(const std::vector<uint8_t>& private_key, const std::string& filename) {
    save_key_to_file(private_key, filename);
}

inline void KeyIO::save_ec_public_key(const std::vector<uint8_t>& public_key, const std::string& filename) {
    save_key_to_file(public_key, filename);
}

inline std::vector<uint8_t> KeyIO::load_ec_private_key(const std::string& filename) {
    return load_key_from_file(filename);
}

inline std::vector<uint8_t> KeyIO::load_ec_public_key(const std::string& filename) {
    return load_key_from_file(filename);
}

// RSA key method implementations
inline void KeyIO::save_rsa_private_key(const std::vector<uint8_t>& private_key, const std::string& filename) {
    save_key_to_file(private_key, filename);
}

inline void KeyIO::save_rsa_public_key(const std::vector<uint8_t>& public_key, const std::string& filename) {
    save_key_to_file(public_key, filename);
}

inline std::vector<uint8_t> KeyIO::load_rsa_private_key(const std::string& filename) {
    return load_key_from_file(filename);
}

inline std::vector<uint8_t> KeyIO::load_rsa_public_key(const std::string& filename) {
    return load_key_from_file(filename);
}

} // namespace utils
} // namespace lockey
