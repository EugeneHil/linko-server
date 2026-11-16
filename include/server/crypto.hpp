// Crypto helpers for the server (design spec 4.5/4.6/6): random identifiers
// and the SPKI pin the apps validate the self-signed certificate against.
// Hashing deliberately reuses linko::sha256Hex from the core submodule -
// this repo has exactly one digest implementation (ADR-0002/ADR-0003).
#pragma once

#include <cstddef>
#include <string>

namespace server {

// Lowercase hex of `bytes` random bytes (2 * bytes characters), from
// OpenSSL RAND_bytes. Throws std::runtime_error only if the operating
// system's entropy source fails - in practice never; callers treat it as
// fatal startup-style error handling.
[[nodiscard]] auto randomHex(std::size_t bytes) -> std::string;

// base64(SHA-256(SPKI DER)) of the certificate at `pemPath` - the pin the
// invite link and the app settings carry. Throws std::runtime_error when
// the file cannot be read or is not a PEM certificate.
[[nodiscard]] auto spkiPinOfCertFile(const std::string &pemPath) -> std::string;

} // namespace server
