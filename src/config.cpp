// Config loader implementation (Plan 3 Task 2).
#include "server/config.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace server {
namespace {

constexpr std::array<const char *, 9> kKnownKeys{
    "bind",       "port",       "dataDir",  "certFile", "keyFile",
    "turnSecret", "publicHost", "turnUris", "limits",
};

constexpr std::array<const char *, 8> kKnownLimitKeys{
    "maxFileBytes",        "userQuotaBytes",     "fileTtlDays",
    "maxSocketsPerDevice", "envelopesPerMinute", "authFailsPerMinute",
    "idleTimeoutSec",      "turnTtlSec",
};

// Empty environment variables count as unset.
auto environmentValue(const char *name) -> const char * {
    const char *value = std::getenv(name);
    return (value != nullptr && value[0] != '\0') ? value : nullptr;
}

[[noreturn]] void throwBadType(const std::string &key, const char *expected) {
    throw std::runtime_error("config: '" + key + "' must be " + expected);
}

auto getString(const nlohmann::json &object, const std::string &key)
    -> std::string {
    if (!object.at(key).is_string()) {
        throwBadType(key, "a string");
    }
    return object.at(key).get<std::string>();
}

auto getInt(const nlohmann::json &object, const std::string &key) -> int {
    if (!object.at(key).is_number_integer()) {
        throwBadType(key, "an integer");
    }
    return object.at(key).get<int>();
}

auto getInt64(const nlohmann::json &object, const std::string &key)
    -> std::int64_t {
    if (!object.at(key).is_number_integer()) {
        throwBadType(key, "an integer");
    }
    return object.at(key).get<std::int64_t>();
}

// Rejects every object key not present in `known`, naming it (with a
// "limits." style prefix) in the error.
template <std::size_t Size>
void assertKnownKeys(const nlohmann::json &object,
                     const std::array<const char *, Size> &known,
                     const std::string &prefix) {
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (std::none_of(
                known.begin(), known.end(),
                [&it](const char *key) -> bool { return it.key() == key; })) {
            throw std::runtime_error("config: unknown key '" + prefix +
                                     it.key() + "'");
        }
    }
}

void applyLimits(const nlohmann::json &limits, Config &config) {
    assertKnownKeys(limits, kKnownLimitKeys, "limits.");
    if (limits.contains("maxFileBytes")) {
        config.limits.maxFileBytes = getInt64(limits, "maxFileBytes");
    }
    if (limits.contains("userQuotaBytes")) {
        config.limits.userQuotaBytes = getInt64(limits, "userQuotaBytes");
    }
    if (limits.contains("fileTtlDays")) {
        config.limits.fileTtlDays = getInt(limits, "fileTtlDays");
    }
    if (limits.contains("maxSocketsPerDevice")) {
        config.limits.maxSocketsPerDevice =
            getInt(limits, "maxSocketsPerDevice");
    }
    if (limits.contains("envelopesPerMinute")) {
        config.limits.envelopesPerMinute = getInt(limits, "envelopesPerMinute");
    }
    if (limits.contains("authFailsPerMinute")) {
        config.limits.authFailsPerMinute = getInt(limits, "authFailsPerMinute");
    }
    if (limits.contains("idleTimeoutSec")) {
        config.limits.idleTimeoutSec = getInt(limits, "idleTimeoutSec");
    }
    if (limits.contains("turnTtlSec")) {
        config.limits.turnTtlSec = getInt(limits, "turnTtlSec");
    }
}

void applyFileValues(const nlohmann::json &root, Config &config) {
    if (root.contains("bind")) {
        config.bind = getString(root, "bind");
    }
    if (root.contains("port")) {
        config.port = getInt(root, "port");
    }
    if (root.contains("dataDir")) {
        config.dataDir = getString(root, "dataDir");
    }
    if (root.contains("certFile")) {
        config.certFile = getString(root, "certFile");
    }
    if (root.contains("keyFile")) {
        config.keyFile = getString(root, "keyFile");
    }
    if (root.contains("turnSecret")) {
        config.turnSecret = getString(root, "turnSecret");
    }
    if (root.contains("publicHost")) {
        config.publicHost = getString(root, "publicHost");
    }
    if (root.contains("turnUris")) {
        if (!root.at("turnUris").is_array()) {
            throwBadType("turnUris", "an array of strings");
        }
        for (const auto &uri : root.at("turnUris")) {
            config.turnUris.push_back(uri.get<std::string>());
        }
    }
    if (root.contains("limits")) {
        if (!root.at("limits").is_object()) {
            throwBadType("limits", "an object");
        }
        applyLimits(root.at("limits"), config);
    }
}

void applyEnvOverrides(Config &config) {
    // Environment wins over the file (design spec 4.5 "Config").
    if (const char *value = environmentValue("LINKO_BIND")) {
        config.bind = value;
    }
    if (const char *value = environmentValue("LINKO_PORT")) {
        try {
            config.port = std::stoi(value);
        } catch (const std::exception &) {
            throw std::runtime_error("config: LINKO_PORT must be an integer");
        }
    }
    if (const char *value = environmentValue("LINKO_DATA_DIR")) {
        config.dataDir = value;
    }
    if (const char *value = environmentValue("LINKO_TLS_CERT")) {
        config.certFile = value;
    }
    if (const char *value = environmentValue("LINKO_TLS_KEY")) {
        config.keyFile = value;
    }
    if (const char *value = environmentValue("LINKO_TURN_SECRET")) {
        config.turnSecret = value;
    }
    if (const char *value = environmentValue("LINKO_PUBLIC_HOST")) {
        config.publicHost = value;
    }
}

void deriveTurnUris(Config &config) {
    if (!config.turnUris.empty()) {
        return;
    }
    config.turnUris.push_back("turn:" + config.publicHost +
                              ":3478?transport=udp");
    config.turnUris.push_back("turn:" + config.publicHost +
                              ":3478?transport=tcp");
}

auto parseJsonFile(const std::string &path) -> nlohmann::json {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("config: cannot open " + path);
    }
    nlohmann::json root;
    try {
        input >> root;
    } catch (const std::exception &error) {
        throw std::runtime_error(std::string("config: invalid JSON in ") +
                                 path + ": " + error.what());
    }
    if (!root.is_object()) {
        throw std::runtime_error("config: root must be a JSON object");
    }
    return root;
}

} // namespace

auto loadConfig(const std::string &path) -> Config {
    const auto root = parseJsonFile(path);
    assertKnownKeys(root, kKnownKeys, "");
    Config config;
    applyFileValues(root, config);
    applyEnvOverrides(config);
    deriveTurnUris(config);
    return config;
}

} // namespace server
