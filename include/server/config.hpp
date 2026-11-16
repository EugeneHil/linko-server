// Server configuration (design spec 4.5): one JSON file plus environment
// variables, env winning over file. Values are placeholders in
// config.example.json; real secrets (TLS key path, TURN shared secret)
// exist only on the host - see spec section 6 and ADR-0003.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace server {

// Rate and size limits (spec 4.5 "Limits"): named defaults so a config file
// may override only what it cares about and tests can compare against them.
inline constexpr std::int64_t kDefaultMaxFileBytes = 100LL * 1024 * 1024;
inline constexpr std::int64_t kDefaultUserQuotaBytes = 1LL * 1024 * 1024 * 1024;
inline constexpr int kDefaultFileTtlDays = 30;
inline constexpr int kDefaultMaxSocketsPerDevice = 1;
inline constexpr int kDefaultEnvelopesPerMinute = 600;
inline constexpr int kDefaultAuthFailsPerMinute = 10;
inline constexpr int kDefaultIdleTimeoutSec = 300;
inline constexpr int kDefaultTurnTtlSec = 3600;

struct Limits {
    std::int64_t maxFileBytes = kDefaultMaxFileBytes;
    std::int64_t userQuotaBytes = kDefaultUserQuotaBytes;
    int fileTtlDays = kDefaultFileTtlDays;
    int maxSocketsPerDevice = kDefaultMaxSocketsPerDevice;
    int envelopesPerMinute = kDefaultEnvelopesPerMinute;
    int authFailsPerMinute = kDefaultAuthFailsPerMinute;
    int idleTimeoutSec = kDefaultIdleTimeoutSec;
    int turnTtlSec = kDefaultTurnTtlSec;
};

inline constexpr int kDefaultPort = 443;

struct Config {
    std::string bind = "0.0.0.0";
    int port = kDefaultPort;
    std::string dataDir = "data";
    std::string certFile;
    std::string keyFile;
    std::string turnSecret;
    std::string publicHost = "localhost";
    std::vector<std::string> turnUris;
    Limits limits;
};

// Loads the JSON config at `path` and applies the LINKO_* environment
// variables on top (LINKO_BIND, LINKO_PORT, LINKO_DATA_DIR, LINKO_TLS_CERT,
// LINKO_TLS_KEY, LINKO_TURN_SECRET, LINKO_PUBLIC_HOST). Unknown keys -
// top level or inside "limits" - are rejected with an error naming the key.
// When "turnUris" is absent, two URIs are derived from publicHost (UDP and
// TCP on 3478). Throws std::runtime_error with a message naming the problem
// key: this runs once at startup, where a misconfiguration must be loud.
[[nodiscard]] auto loadConfig(const std::string &path) -> Config;

} // namespace server
