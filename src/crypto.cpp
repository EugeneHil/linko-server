// Crypto helpers implementation (Plan 3 Task 3).
#include "server/crypto.hpp"

#include <stdexcept>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "linko/sha256.hpp"

namespace server {
namespace {

constexpr std::array<char, 16> kHexDigits{
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

constexpr unsigned int kLowNibbleMask = 0x0FU;
constexpr int kSpkiPinBufferBytes = 64;

} // namespace

auto randomHex(std::size_t bytes) -> std::string {
    std::vector<unsigned char> raw(bytes);
    if (RAND_bytes(raw.data(), static_cast<int>(bytes)) != 1) {
        throw std::runtime_error("crypto: RAND_bytes failed");
    }
    std::string hex;
    hex.reserve(bytes * 2);
    for (const unsigned char byte : raw) {
        const auto bits = static_cast<unsigned int>(byte);
        hex.push_back(kHexDigits[static_cast<std::size_t>(bits >> 4U)]);
        hex.push_back(
            kHexDigits[static_cast<std::size_t>(bits & kLowNibbleMask)]);
    }
    return hex;
}

auto spkiPinOfCertFile(const std::string &pemPath) -> std::string {
    BIO *file = BIO_new_file(pemPath.c_str(), "r");
    if (file == nullptr) {
        throw std::runtime_error("crypto: cannot open certificate " + pemPath);
    }
    X509 *certificate = PEM_read_bio_X509(file, nullptr, nullptr, nullptr);
    BIO_free(file);
    if (certificate == nullptr) {
        throw std::runtime_error("crypto: not a PEM certificate: " + pemPath);
    }
    const EVP_PKEY *publicKey = X509_get0_pubkey(certificate);
    const int derLength = i2d_PUBKEY(publicKey, nullptr);
    if (derLength <= 0) {
        X509_free(certificate);
        throw std::runtime_error("crypto: cannot encode SPKI of " + pemPath);
    }
    std::vector<unsigned char> der(static_cast<std::size_t>(derLength));
    unsigned char *cursor = der.data();
    static_cast<void>(i2d_PUBKEY(publicKey, &cursor));
    X509_free(certificate);

    // The digest implementation is the core's (no second SHA-256 here).
    const linko::Sha256Digest digest = linko::sha256(der);
    std::array<unsigned char, kSpkiPinBufferBytes> encoded{};
    const int encodedLength =
        EVP_EncodeBlock(encoded.data(), digest.data(),
                        static_cast<int>(linko::kSha256DigestBytes));
    return {reinterpret_cast<const char *>(encoded.data()),
            static_cast<std::size_t>(encodedLength)};
}

} // namespace server
