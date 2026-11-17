// cert generate (Plan 3 Task 10): the CLI command writes an owner-only key
// and a world-readable self-signed P-256 certificate (CN=linko, 3650 days),
// and the SPKI pin it prints is the pin of the written certificate. POSIX
// mode assertions are compiled out on Windows, where the owner-only
// guarantee comes from the key's DACL instead.
#include <sys/stat.h>

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "server/cli.hpp"
#include "server/crypto.hpp"
#include "util/captured_stdout.hpp"
#include "util/test_cert.hpp"

namespace fs = std::filesystem;

namespace {

constexpr unsigned int kModeMask = 0777U;
constexpr unsigned int kOwnerOnlyMode = 0600U;
constexpr unsigned int kWorldReadableMode = 0644U;
constexpr int kP256Bits = 256;
constexpr int kCertValidityDays = 3650;
constexpr std::size_t kCommonNameBufferBytes = 64;

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - argv layout is
// (executable, arguments...).
auto runCli(const std::vector<std::string> &arguments) -> int {
    std::vector<char *> argv;
    argv.push_back(const_cast<char *>("linko-server"));
    for (const auto &argument : arguments) {
        argv.push_back(const_cast<char *>(argument.c_str()));
    }
    return server::runCli(static_cast<int>(argv.size()), argv.data());
}

// A fresh output directory per test: temp dirs persist across runs, so a
// leftover pair from an earlier run must not satisfy this run's assertions.
auto certOutDir(const std::string &name) -> std::string {
    const auto dir = fs::path(::testing::TempDir()) / ("linko-certgen-" + name);
    std::error_code ignored;
    fs::remove_all(dir, ignored);
    return dir.string();
}

struct StatResult {
    bool ok = false;
    unsigned int mode = 0;
};

auto fileMode(const std::string &path) -> StatResult {
    struct stat info = {};
    if (::stat(path.c_str(), &info) != 0) {
        return {false, 0};
    }
    return {true, static_cast<unsigned int>(info.st_mode) & kModeMask};
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - the (outDir, suffix)
// pair is the same shape both call sites use.
auto pairPath(const std::string &outDir, const char *suffix) -> std::string {
    return (fs::path(outDir) / ("server." + std::string(suffix))).string();
}

} // namespace

TEST(Cert, GenerateCreatesOwnerOnlyKey) {
    const std::string outDir = certOutDir("owner-key");
    const std::string keyPath = pairPath(outDir, "key");
    const std::string certPath = pairPath(outDir, "crt");
    EXPECT_EQ(runCli({"cert", "generate", "--out", outDir}), 0);
    ASSERT_TRUE(fs::exists(keyPath));
    ASSERT_TRUE(fs::exists(certPath));
#ifndef _WIN32
    const StatResult keyMode = fileMode(keyPath);
    ASSERT_TRUE(keyMode.ok) << std::strerror(errno);
    EXPECT_EQ(keyMode.mode, kOwnerOnlyMode);
    const StatResult certMode = fileMode(certPath);
    ASSERT_TRUE(certMode.ok) << std::strerror(errno);
    EXPECT_EQ(certMode.mode, kWorldReadableMode);
#endif
}

TEST(Cert, IsSelfSignedP256) {
    const std::string outDir = certOutDir("self-signed");
    const std::string keyPath = pairPath(outDir, "key");
    const std::string certPath = pairPath(outDir, "crt");
    EXPECT_EQ(runCli({"cert", "generate", "--out", outDir}), 0);

    BIO *file = BIO_new_file(certPath.c_str(), "r");
    ASSERT_NE(file, nullptr);
    X509 *raw = PEM_read_bio_X509(file, nullptr, nullptr, nullptr);
    BIO_free(file);
    ASSERT_NE(raw, nullptr);
    const std::unique_ptr<X509, decltype(&X509_free)> certificate(raw,
                                                                  X509_free);

    // Self-signed: issuer equals subject and the signature verifies with
    // the certificate's own public key.
    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(certificate.get()),
                            X509_get_issuer_name(certificate.get())),
              0);
    EXPECT_EQ(X509_self_signed(certificate.get(), 1), 1);

    // ECDSA P-256, CN=linko, 3650-day validity.
    const EVP_PKEY *publicKey = X509_get0_pubkey(certificate.get());
    ASSERT_NE(publicKey, nullptr);
    EXPECT_EQ(EVP_PKEY_get_base_id(publicKey), EVP_PKEY_EC);
    EXPECT_EQ(EVP_PKEY_get_bits(publicKey), kP256Bits);
    std::array<char, kCommonNameBufferBytes> commonName{};
    ASSERT_GT(X509_NAME_get_text_by_NID(
                  X509_get_subject_name(certificate.get()), NID_commonName,
                  commonName.data(), static_cast<int>(commonName.size())),
              0);
    EXPECT_STREQ(commonName.data(), "linko");
    int days = 0;
    int seconds = 0;
    ASSERT_EQ(ASN1_TIME_diff(&days, &seconds,
                             X509_getm_notBefore(certificate.get()),
                             X509_getm_notAfter(certificate.get())),
              1);
    EXPECT_EQ(days, kCertValidityDays);

    // The written key belongs to the certificate.
    BIO *keyFile = BIO_new_file(keyPath.c_str(), "r");
    ASSERT_NE(keyFile, nullptr);
    EVP_PKEY *rawKey =
        PEM_read_bio_PrivateKey(keyFile, nullptr, nullptr, nullptr);
    BIO_free(keyFile);
    ASSERT_NE(rawKey, nullptr);
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        rawKey, EVP_PKEY_free);
    EXPECT_EQ(EVP_PKEY_eq(publicKey, key.get()), 1);
}

TEST(Cert, PinPrinted) {
    const std::string outDir = certOutDir("pin");
    const std::string certPath = pairPath(outDir, "crt");
    // Assert outside the capture scope: gtest failure text printed inside
    // it would land in the capture file and never reach the CI log.
    int exitCode = -1;
    std::string output;
    {
        test_util::CapturedStdout capture("pin");
        exitCode = runCli({"cert", "generate", "--out", outDir});
        output = capture.content();
    }
    const std::string pin = server::spkiPinOfCertFile(certPath);
    EXPECT_EQ(exitCode, 0);
    EXPECT_FALSE(pin.empty());
    EXPECT_NE(output.find("pin: " + pin), std::string::npos) << output;
}

TEST(Cert, GenerateWithoutValueForOutExits2) {
    EXPECT_EQ(runCli({"cert", "generate", "--out"}), 2);
}
