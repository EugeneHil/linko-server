// Ephemeral certificate helper for integration tests (Plan 3 Tasks 3+).
// Builds a self-signed EC P-256 certificate and key through the OpenSSL API
// into GoogleTest's per-test temp directory. No key material is ever
// committed or written outside the temp dir.
#pragma once

#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>

namespace test_util {

// MSVC deprecates fopen (C4996, and warnings are errors); fopen_s is the
// sanctioned spelling there. Returns nullptr when the file cannot be
// opened.
inline auto openFile(const std::string &path, const char *mode) -> FILE * {
#if defined(_WIN32)
    FILE *file = nullptr;
    static_cast<void>(fopen_s(&file, path.c_str(), mode));
    return file;
#else
    return std::fopen(path.c_str(), mode);
#endif
}

// Returns {certPemPath, keyPemPath} for a throwaway self-signed P-256 pair.
inline auto makeEphemeralCert(const std::string &name)
    -> std::pair<std::string, std::string> {
    namespace fs = std::filesystem;
    const fs::path dir =
        fs::path(::testing::TempDir()) / ("linko-cert-" + name);
    std::error_code ignored;
    fs::create_directories(dir, ignored);
    const std::string certPath = (dir / "server.crt").string();
    const std::string keyPath = (dir / "server.key").string();

    EVP_PKEY_CTX *keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY *pkey = nullptr;
    static_cast<void>(EVP_PKEY_keygen_init(keyContext));
    static_cast<void>(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
        keyContext, NID_X9_62_prime256v1));
    static_cast<void>(EVP_PKEY_keygen(keyContext, &pkey));
    EVP_PKEY_CTX_free(keyContext);

    X509 *certificate = X509_new();
    static_cast<void>(X509_set_version(certificate, 2));
    static_cast<void>(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1));
    static_cast<void>(X509_gmtime_adj(X509_getm_notBefore(certificate), 0));
    static_cast<void>(X509_gmtime_adj(X509_getm_notAfter(certificate), 3600));
    static_cast<void>(X509_set_pubkey(certificate, pkey));
    X509_NAME *subject = X509_get_subject_name(certificate);
    static_cast<void>(X509_NAME_add_entry_by_txt(
        subject, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>("linko-test"), -1, -1, 0));
    static_cast<void>(X509_sign(certificate, pkey, EVP_sha256()));

    if (FILE *certFile = openFile(certPath, "wb")) {
        static_cast<void>(PEM_write_X509(certFile, certificate));
        static_cast<void>(std::fclose(certFile));
    }
    if (FILE *keyFile = openFile(keyPath, "wb")) {
        static_cast<void>(PEM_write_PrivateKey(keyFile, pkey, nullptr, nullptr,
                                               0, nullptr, nullptr));
        static_cast<void>(std::fclose(keyFile));
    }
#if !defined(_WIN32)
    static_cast<void>(::chmod(keyPath.c_str(), 0600));
#endif
    X509_free(certificate);
    EVP_PKEY_free(pkey);
    return {certPath, keyPath};
}

} // namespace test_util
