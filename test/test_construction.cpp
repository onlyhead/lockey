#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "lockey/lockey.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Construction and Configuration") {
    TEST_CASE("Default constructor") {
        REQUIRE_NOTHROW(lockey::Lockey crypto);

        lockey::Lockey crypto;
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::AES_256_GCM);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA256);
    }

    TEST_CASE("Constructor with parameters") {
        REQUIRE_NOTHROW(
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_128_GCM, lockey::Lockey::HashAlgorithm::SHA512));

        lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_128_GCM, lockey::Lockey::HashAlgorithm::SHA512);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::AES_128_GCM);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA512);
    }

    TEST_CASE("Algorithm setting") {
        lockey::Lockey crypto;

        crypto.set_algorithm(lockey::Lockey::Algorithm::ChaCha20_Poly1305);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::ChaCha20_Poly1305);

        crypto.set_algorithm(lockey::Lockey::Algorithm::RSA_2048);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::RSA_2048);

        crypto.set_algorithm(lockey::Lockey::Algorithm::ECDSA_P256);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::ECDSA_P256);
    }

    TEST_CASE("Hash algorithm setting") {
        lockey::Lockey crypto;

        crypto.set_hash_algorithm(lockey::Lockey::HashAlgorithm::SHA384);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA384);

        crypto.set_hash_algorithm(lockey::Lockey::HashAlgorithm::SHA512);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA512);
    }

    TEST_CASE("Unsupported algorithms throw exceptions") {
        // Test BLAKE2b - should throw
        CHECK_THROWS_AS(
            lockey::Lockey crypto(lockey::Lockey::Algorithm::AES_256_GCM, lockey::Lockey::HashAlgorithm::BLAKE2b),
            std::runtime_error);

        // Test Ed25519 - should throw
        CHECK_THROWS_AS(lockey::Lockey crypto(lockey::Lockey::Algorithm::Ed25519), std::runtime_error);
    }
}
