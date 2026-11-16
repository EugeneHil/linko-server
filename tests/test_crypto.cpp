// Crypto helpers (Plan 3 Task 3): randomHex shape, the core-digest KAT tie,
// and the SPKI pin cross-checked against an independent OpenSSL computation.
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "linko/sha256.hpp"
#include "server/crypto.hpp"
#include "util/test_cert.hpp"

namespace {

constexpr int kPinBufferBytes = 64;

// Derives base64(SHA-256(SPKI DER)) through a different OpenSSL path than
// server::spkiPinOfCertFile uses (in-memory parse, EVP_Digest,
// EVP_EncodeBlock).
auto independentPin(const std::string &certPath) -> std::string {
    BIO *file = BIO_new_file(certPath.c_str(), "r");
    X509 *certificate = PEM_read_bio_X509(file, nullptr, nullptr, nullptr);
    BIO_free(file);
    if (certificate == nullptr) {
        return {};
    }
    const EVP_PKEY *publicKey = X509_get0_pubkey(certificate);
    const int derLength = i2d_PUBKEY(publicKey, nullptr);
    std::vector<unsigned char> der(static_cast<std::size_t>(derLength));
    unsigned char *cursor = der.data();
    static_cast<void>(i2d_PUBKEY(publicKey, &cursor));
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;
    EVP_Digest(der.data(), static_cast<int>(der.size()), digest.data(),
               &digestLength, EVP_sha256(), nullptr);
    std::array<unsigned char, kPinBufferBytes> encoded{};
    const int encodedLength = EVP_EncodeBlock(encoded.data(), digest.data(),
                                              static_cast<int>(digestLength));
    X509_free(certificate);
    return {reinterpret_cast<const char *>(encoded.data()),
            static_cast<std::size_t>(encodedLength)};
}

} // namespace

TEST(Crypto, RandomHexLengthAndCharset) {
    const auto value = server::randomHex(16);
    ASSERT_EQ(value.size(), 32U);
    for (const char digit : value) {
        EXPECT_TRUE((digit >= '0' && digit <= '9') ||
                    (digit >= 'a' && digit <= 'f'))
            << "unexpected character: " << digit;
    }
}

TEST(Crypto, RandomHexUnique) {
    EXPECT_NE(server::randomHex(16), server::randomHex(16));
}

TEST(Crypto, Sha256DelegatesToCoreKat) {
    // FIPS 180-4 known answer, computed through linko::sha256Hex - the only
    // digest implementation this repository uses (ADR-0002/0003).
    const std::vector<std::uint8_t> input{'a', 'b', 'c'};
    EXPECT_EQ(
        linko::sha256Hex(input),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Crypto, SpkiPinMatchesIndependentComputation) {
    const auto paths = test_util::makeEphemeralCert("pin");
    const auto &[certPath, keyPath] = paths;
    static_cast<void>(keyPath);
    EXPECT_FALSE(certPath.empty());
    EXPECT_EQ(server::spkiPinOfCertFile(certPath), independentPin(certPath));
}

TEST(Crypto, SpkiPinRejectsNonCertificate) {
    EXPECT_THROW(
        static_cast<void>(server::spkiPinOfCertFile("/nonexistent.pem")),
        std::exception);
}
