#pragma once

#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace lockey {
    namespace utils {

        /**
         * @brief Key format types
         */
        enum class KeyFormat {
            PEM, ///< PEM format (Base64 encoded)
            DER, ///< DER format (binary)
            RAW  ///< Raw binary format
        };

        /**
         * @brief Common utility functions and constants
         */
        class Common {
          public:
            // Common cryptographic constants
            static constexpr size_t AES_128_KEY_SIZE = 16;
            static constexpr size_t AES_256_KEY_SIZE = 32;
            static constexpr size_t AES_BLOCK_SIZE = 16;
            static constexpr size_t GCM_IV_SIZE = 12;
            static constexpr size_t GCM_TAG_SIZE = 16;

            static constexpr size_t SHA256_DIGEST_SIZE = 32;
            static constexpr size_t SHA384_DIGEST_SIZE = 48;
            static constexpr size_t SHA512_DIGEST_SIZE = 64;

            static constexpr size_t RSA_2048_KEY_SIZE = 256;
            static constexpr size_t RSA_4096_KEY_SIZE = 512;

            static constexpr size_t P256_KEY_SIZE = 32;
            static constexpr size_t P384_KEY_SIZE = 48;
            static constexpr size_t P521_KEY_SIZE = 66;

            /**
             * @brief Generate secure random bytes
             * @param size Number of bytes to generate
             * @return Random bytes
             */
            static std::vector<uint8_t> generate_random_bytes(size_t size);

            /**
             * @brief Constant-time memory comparison
             * @param a First buffer
             * @param b Second buffer
             * @param size Size to compare
             * @return true if equal, false otherwise
             */
            static bool secure_compare(const uint8_t *a, const uint8_t *b, size_t size);

            /**
             * @brief Secure memory clear
             * @param data Buffer to clear
             * @param size Size of buffer
             */
            static void secure_clear(uint8_t *data, size_t size);

            /**
             * @brief Convert bytes to hex string
             * @param data Data to convert
             * @return Hex string
             */
            static std::string bytes_to_hex(const std::vector<uint8_t> &data);

            /**
             * @brief Convert hex string to bytes
             * @param hex Hex string
             * @return Converted bytes
             */
            static std::vector<uint8_t> hex_to_bytes(const std::string &hex);

            /**
             * @brief XOR two byte arrays
             * @param a First array
             * @param b Second array
             * @return XOR result
             */
            static std::vector<uint8_t> xor_bytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);

            /**
             * @brief PKCS#7 padding
             * @param data Data to pad
             * @param block_size Block size for padding
             * @return Padded data
             */
            static std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t> &data, size_t block_size);

            /**
             * @brief Remove PKCS#7 padding
             * @param data Padded data
             * @return Unpadded data
             */
            static std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t> &data);

          private:
            static uint8_t hex_char_to_byte(char c);
            static char byte_to_hex_char(uint8_t b);
        };

        // Inline implementations
        inline std::vector<uint8_t> Common::generate_random_bytes(size_t size) {
            std::vector<uint8_t> bytes(size);
            // Use system random number generator
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);

            for (size_t i = 0; i < size; ++i) {
                bytes[i] = static_cast<uint8_t>(dis(gen));
            }

            return bytes;
        }

        inline bool Common::secure_compare(const uint8_t *a, const uint8_t *b, size_t size) {
            uint8_t result = 0;
            for (size_t i = 0; i < size; ++i) {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        inline void Common::secure_clear(uint8_t *data, size_t size) {
            volatile uint8_t *p = data;
            for (size_t i = 0; i < size; ++i) {
                p[i] = 0;
            }
        }

        inline std::string Common::bytes_to_hex(const std::vector<uint8_t> &data) {
            std::string hex;
            hex.reserve(data.size() * 2);

            for (uint8_t byte : data) {
                hex += byte_to_hex_char((byte >> 4) & 0x0F);
                hex += byte_to_hex_char(byte & 0x0F);
            }

            return hex;
        }

        inline std::vector<uint8_t> Common::hex_to_bytes(const std::string &hex) {
            if (hex.size() % 2 != 0) {
                return {}; // Return empty vector for invalid length instead of throwing
            }

            std::vector<uint8_t> bytes;
            bytes.reserve(hex.size() / 2);

            try {
                for (size_t i = 0; i < hex.size(); i += 2) {
                    uint8_t byte = (hex_char_to_byte(hex[i]) << 4) | hex_char_to_byte(hex[i + 1]);
                    bytes.push_back(byte);
                }
            } catch (const std::invalid_argument &) {
                return {}; // Return empty vector for invalid characters instead of throwing
            }

            return bytes;
        }

        inline std::vector<uint8_t> Common::xor_bytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
            if (a.size() != b.size()) {
                throw std::invalid_argument("Arrays must be same size for XOR");
            }

            std::vector<uint8_t> result(a.size());
            for (size_t i = 0; i < a.size(); ++i) {
                result[i] = a[i] ^ b[i];
            }

            return result;
        }

        inline std::vector<uint8_t> Common::pkcs7_pad(const std::vector<uint8_t> &data, size_t block_size) {
            if (block_size > 255) {
                throw std::invalid_argument("Block size too large for PKCS#7");
            }

            size_t padding_length = block_size - (data.size() % block_size);
            std::vector<uint8_t> padded = data;
            padded.resize(data.size() + padding_length, static_cast<uint8_t>(padding_length));

            return padded;
        }

        inline std::vector<uint8_t> Common::pkcs7_unpad(const std::vector<uint8_t> &data) {
            if (data.empty()) {
                throw std::invalid_argument("Cannot unpad empty data");
            }

            uint8_t padding_length = data.back();
            if (padding_length == 0 || padding_length > data.size()) {
                throw std::invalid_argument("Invalid PKCS#7 padding");
            }

            // Verify padding
            for (size_t i = data.size() - padding_length; i < data.size(); ++i) {
                if (data[i] != padding_length) {
                    throw std::invalid_argument("Invalid PKCS#7 padding");
                }
            }

            return std::vector<uint8_t>(data.begin(), data.end() - padding_length);
        }

        inline uint8_t Common::hex_char_to_byte(char c) {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            throw std::invalid_argument("Invalid hex character");
        }

        inline char Common::byte_to_hex_char(uint8_t b) { return (b < 10) ? ('0' + b) : ('a' + b - 10); }

        // Convenience standalone functions for easier usage
        inline std::string to_hex(const std::vector<uint8_t> &data) { return Common::bytes_to_hex(data); }

        inline std::vector<uint8_t> from_hex(const std::string &hex) { return Common::hex_to_bytes(hex); }

    } // namespace utils
} // namespace lockey
