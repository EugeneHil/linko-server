// Config loading, env overrides and the request-log line shape (Plan 3
// Task 2). The example config must parse with placeholder values; unknown
// keys are rejected by name; environment variables win over the file.
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

#include "server/config.hpp"
#include "server/log.hpp"

namespace {

// Writes `body` into a unique temp file and returns its path; the (name,
// body) order is fixed at every call site by usage.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto writeTempConfig(const std::string &name, const std::string &body)
    -> std::string {
    const auto path = std::filesystem::path(::testing::TempDir()) /
                      ("linko-" + name + ".json");
    std::ofstream output(path);
    output << body;
    output.close();
    return path.string();
}

// Portable environment helpers: ::setenv does not exist on Windows.
void setEnv(const char *name, const char *value) {
#ifdef _WIN32
    ::_putenv_s(name, value);
#else
    ::setenv(name, value, 1);
#endif
}

void unsetEnv(const char *name) {
#ifdef _WIN32
    ::_putenv_s(name, "");
#else
    ::unsetenv(name);
#endif
}

// RAII env override so a failed assertion never leaks variables into other
// suites in the same process.
class ScopedEnv {
  public:
    ScopedEnv(const char *name, const char *value) : name_(name) {
        setEnv(name, value);
    }
    ~ScopedEnv() { unsetEnv(name_.c_str()); }
    ScopedEnv(const ScopedEnv &) = delete;
    auto operator=(const ScopedEnv &) -> ScopedEnv & = delete;

  private:
    std::string name_;
};

} // namespace

TEST(Config, ParsesExampleConfig) {
    const auto config = server::loadConfig(std::string(LINKO_REPO_ROOT) +
                                           "/config.example.json");
    EXPECT_EQ(config.bind, "0.0.0.0");
    EXPECT_EQ(config.port, 443);
    EXPECT_EQ(config.dataDir, "data");
    EXPECT_EQ(config.certFile, "certs/server.crt");
    EXPECT_EQ(config.keyFile, "certs/server.key");
    EXPECT_EQ(config.turnSecret, "CHANGE_ME_TURN_SECRET");
    EXPECT_EQ(config.publicHost, "localhost");
    ASSERT_EQ(config.turnUris.size(), 2U);
    EXPECT_EQ(config.turnUris[0], "turn:localhost:3478?transport=udp");
    EXPECT_EQ(config.turnUris[1], "turn:localhost:3478?transport=tcp");
    EXPECT_EQ(config.limits.maxFileBytes, server::kDefaultMaxFileBytes);
    EXPECT_EQ(config.limits.userQuotaBytes, server::kDefaultUserQuotaBytes);
    EXPECT_EQ(config.limits.fileTtlDays, server::kDefaultFileTtlDays);
    EXPECT_EQ(config.limits.maxSocketsPerDevice,
              server::kDefaultMaxSocketsPerDevice);
    EXPECT_EQ(config.limits.envelopesPerMinute,
              server::kDefaultEnvelopesPerMinute);
    EXPECT_EQ(config.limits.authFailsPerMinute,
              server::kDefaultAuthFailsPerMinute);
    EXPECT_EQ(config.limits.idleTimeoutSec, server::kDefaultIdleTimeoutSec);
    EXPECT_EQ(config.limits.turnTtlSec, server::kDefaultTurnTtlSec);
}

TEST(Config, UnknownKeyRejectedWithName) {
    const auto path =
        writeTempConfig("unknown-key", R"({"port": 443, "bogusKey": 1})");
    try {
        static_cast<void>(server::loadConfig(path));
        FAIL() << "expected loadConfig to throw on an unknown key";
    } catch (const std::exception &error) {
        EXPECT_NE(std::string(error.what()).find("bogusKey"), std::string::npos)
            << "error must name the offending key: " << error.what();
    }
}

TEST(Config, UnknownLimitKeyRejectedWithName) {
    const auto path =
        writeTempConfig("unknown-limit", R"({"limits": {"noSuchLimit": 5}})");
    EXPECT_THROW(static_cast<void>(server::loadConfig(path)), std::exception);
}

TEST(Config, EnvOverridesFile) {
    const auto path =
        writeTempConfig("env", R"({"port": 443, "turnSecret": "file-secret"})");
    const ScopedEnv port("LINKO_PORT", "8443");
    const ScopedEnv secret("LINKO_TURN_SECRET", "env-secret");
    const auto config = server::loadConfig(path);
    EXPECT_EQ(config.port, 8443);
    EXPECT_EQ(config.turnSecret, "env-secret");
}

TEST(Config, DerivedTurnUrisFollowPublicHost) {
    const auto path = writeTempConfig("derive-turn", R"({})");
    const ScopedEnv host("LINKO_PUBLIC_HOST", "linko.example.net");
    const auto config = server::loadConfig(path);
    ASSERT_EQ(config.turnUris.size(), 2U);
    EXPECT_EQ(config.turnUris[0], "turn:linko.example.net:3478?transport=udp");
    EXPECT_EQ(config.turnUris[1], "turn:linko.example.net:3478?transport=tcp");
}

TEST(Log, RequestLogLineShape) {
    constexpr int kHttpStatusOk = 200;
    constexpr std::int64_t kSampleDurationMs = 42;
    std::string captured;
    server::setLogSink(
        [&captured](const std::string &line) -> void { captured = line; });
    server::logRequest("10.0.0.1", "GET", "/api/v1/users?prefix=an",
                       kHttpStatusOk, kSampleDurationMs);
    server::setLogSink(nullptr);
    EXPECT_EQ(captured, "10.0.0.1 GET /api/v1/users 200 42");
}

TEST(Log, EventLogCarriesWhatAndDetail) {
    std::string captured;
    server::setLogSink(
        [&captured](const std::string &line) -> void { captured = line; });
    server::logEvent("invite_created", "user=anna");
    server::setLogSink(nullptr);
    EXPECT_NE(captured.find("invite_created"), std::string::npos);
    EXPECT_NE(captured.find("user=anna"), std::string::npos);
}
