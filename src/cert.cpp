// Certificate generation (Plan 3 Task 10): the `cert generate` CLI command
// builds a self-signed ECDSA P-256 pair through the OpenSSL API. The key is
// written owner-only and never leaves the host it belongs to (design spec 6)
// - generation is expected to run on the VPS (docs/deploy.md).
#include "server/crypto.hpp"

#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

namespace server {
namespace {

constexpr const char *kCertCommonName = "linko";
constexpr const char *kCertFileName = "server.crt";
constexpr const char *kKeyFileName = "server.key";
constexpr long kCertValidityDays = 3650;
constexpr long kSecondsPerDay = 86400;
constexpr int kSerialBytes = 8;
// Keeps the serial ASN.1 INTEGER positive (top bit cleared).
constexpr unsigned char kSerialHighBitMask = 0x7FU;

#ifndef _WIN32
constexpr unsigned int kOwnerOnlyMode = 0600U;
constexpr unsigned int kWorldReadableMode = 0644U;
#endif

struct X509Deleter {
    auto operator()(X509 *certificate) const -> void { X509_free(certificate); }
};

struct EvpPkeyDeleter {
    auto operator()(EVP_PKEY *key) const -> void { EVP_PKEY_free(key); }
};

struct Asn1IntegerDeleter {
    auto operator()(ASN1_INTEGER *value) const -> void {
        ASN1_INTEGER_free(value);
    }
};

auto makeP256Key() -> std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (context == nullptr) {
        throw std::runtime_error("cert: cannot allocate the key context");
    }
    EVP_PKEY *key = nullptr;
    const bool generated = EVP_PKEY_keygen_init(context) == 1 &&
                           EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                               context, NID_X9_62_prime256v1) == 1 &&
                           EVP_PKEY_keygen(context, &key) == 1;
    EVP_PKEY_CTX_free(context);
    if (!generated) {
        throw std::runtime_error("cert: cannot generate the P-256 key");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(key);
}

// Self-signed by construction: the subject doubles as the issuer, the
// signature is the subject key itself. No extensions - the apps validate
// the certificate through the SPKI pin, not a chain.
auto makeSelfSignedCert(EVP_PKEY *key) -> std::unique_ptr<X509, X509Deleter> {
    std::unique_ptr<X509, X509Deleter> certificate(X509_new());
    if (certificate == nullptr) {
        throw std::runtime_error("cert: cannot allocate the certificate");
    }
    std::array<unsigned char, kSerialBytes> serialBytes{};
    if (RAND_bytes(serialBytes.data(), kSerialBytes) != 1) {
        throw std::runtime_error("cert: cannot generate the serial number");
    }
    serialBytes.front() &= kSerialHighBitMask;
    BIGNUM *serial = BN_bin2bn(serialBytes.data(), kSerialBytes, nullptr);
    if (serial == nullptr) {
        throw std::runtime_error("cert: cannot encode the serial number");
    }
    const std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter> serialNumber(
        BN_to_ASN1_INTEGER(serial, nullptr));
    BN_free(serial);
    if (serialNumber == nullptr) {
        throw std::runtime_error("cert: cannot convert the serial number");
    }
    if (X509_set_version(certificate.get(), 2) != 1 ||
        X509_set_serialNumber(certificate.get(), serialNumber.get()) != 1 ||
        X509_set_pubkey(certificate.get(), key) != 1) {
        throw std::runtime_error("cert: cannot fill the certificate");
    }
    static_cast<void>(
        X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0));
    static_cast<void>(X509_gmtime_adj(X509_getm_notAfter(certificate.get()),
                                      kCertValidityDays * kSecondsPerDay));
    X509_NAME *subject = X509_get_subject_name(certificate.get());
    if (X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(kCertCommonName), -1, -1,
            0) != 1 ||
        X509_set_issuer_name(certificate.get(), subject) != 1) {
        throw std::runtime_error("cert: cannot set the subject and issuer");
    }
    if (X509_sign(certificate.get(), key, EVP_sha256()) == 0) {
        throw std::runtime_error("cert: cannot sign the certificate");
    }
    return certificate;
}

void writeCertificateFile(const std::string &path, X509 *certificate) {
    FILE *file = std::fopen(path.c_str(), "wb");
    if (file == nullptr) {
        throw std::runtime_error("cert: cannot write " + path);
    }
    const bool written = PEM_write_X509(file, certificate) == 1;
    static_cast<void>(std::fclose(file));
    if (!written) {
        throw std::runtime_error("cert: cannot write " + path);
    }
}

void writeKeyFile(const std::string &path, EVP_PKEY *key) {
    FILE *file = std::fopen(path.c_str(), "wb");
    if (file == nullptr) {
        throw std::runtime_error("cert: cannot write " + path);
    }
    const bool written = PEM_write_PrivateKey(file, key, nullptr, nullptr, 0,
                                              nullptr, nullptr) == 1;
    static_cast<void>(std::fclose(file));
    if (!written) {
        throw std::runtime_error("cert: cannot write " + path);
    }
}

#ifdef _WIN32
// One allowed WinAPI use (Plan 3 Task 10): rewrite the key file's DACL to
// its owner alone - the Windows equivalent of POSIX 0600. The service runs
// as LocalSystem, which bypasses the DACL and keeps access.
void restrictKeyToOwner(const std::string &path) {
    const std::wstring widePath = std::filesystem::path(path).wstring();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    if (GetNamedSecurityInfoW(widePath.c_str(), SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION, &owner, nullptr,
                              nullptr, nullptr, &descriptor) != ERROR_SUCCESS) {
        throw std::runtime_error("cert: cannot read the key owner of " + path);
    }
    EXPLICIT_ACCESSW entry = {};
    entry.grfAccessPermissions = GENERIC_ALL;
    entry.grfAccessMode = SET_ACCESS;
    entry.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(owner);
    PACL newAcl = nullptr;
    if (SetEntriesInAclW(1, &entry, nullptr, &newAcl) != ERROR_SUCCESS) {
        LocalFree(descriptor);
        throw std::runtime_error("cert: cannot build the key DACL of " + path);
    }
    const DWORD applied = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(widePath.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr);
    LocalFree(newAcl);
    LocalFree(descriptor);
    if (applied != ERROR_SUCCESS) {
        throw std::runtime_error("cert: cannot restrict the key DACL of " +
                                 path);
    }
}

// Windows grants reads through the inherited ACLs; no explicit widening.
auto setWorldReadable(const std::string & /*path*/) -> void {}

#else

// The POSIX 0600 counterpart of the Windows DACL rewrite above.
void restrictKeyToOwner(const std::string &path) {
    if (::chmod(path.c_str(), kOwnerOnlyMode) != 0) {
        throw std::runtime_error("cert: cannot restrict the key mode of " +
                                 path);
    }
}

void setWorldReadable(const std::string &path) {
    if (::chmod(path.c_str(), kWorldReadableMode) != 0) {
        throw std::runtime_error("cert: cannot set the certificate mode of " +
                                 path);
    }
}

#endif

} // namespace

auto generateSelfSignedCert(const std::string &outDir) -> GeneratedCertPaths {
    namespace fs = std::filesystem;
    std::error_code fsError;
    fs::create_directories(outDir, fsError);
    if (fsError) {
        throw std::runtime_error("cert: cannot create " + outDir + ": " +
                                 fsError.message());
    }
    const auto key = makeP256Key();
    const auto certificate = makeSelfSignedCert(key.get());
    const std::string certPath = (fs::path(outDir) / kCertFileName).string();
    const std::string keyPath = (fs::path(outDir) / kKeyFileName).string();
    writeCertificateFile(certPath, certificate.get());
    writeKeyFile(keyPath, key.get());
    restrictKeyToOwner(keyPath);
    setWorldReadable(certPath);
    return {certPath, keyPath};
}

} // namespace server
