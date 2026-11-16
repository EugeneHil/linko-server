// CLI (Plan 3 Task 3): join links with QR output, hash-only invite storage,
// TTL flag, user/device listing and revocation, usage exit code. stdout is
// captured around each runCli call; databases live in the per-test temp dir.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

#include "linko/sha256.hpp"
#include "server/cli.hpp"
#include "server/store.hpp"
#include "util/test_cert.hpp"

namespace {

constexpr std::int64_t kSecondsPerHour = 3600;
constexpr std::int64_t kMsPerSecond = 1000;
constexpr std::int64_t kHourMs = kSecondsPerHour * kMsPerSecond;
constexpr std::int64_t kTtlHoursMs = 2 * kHourMs;
constexpr std::int64_t kPastTtlMs = 60 * kMsPerSecond;
// UTF-8 upper-half block character, the QR output marker.
constexpr const char *kQrBlock = "\xE2\x96\x80";

// Redirects FILE* stdout into a temp file for the lifetime of this object
// and restores it afterwards. runCli prints through stdout, so its output
// is fully captured.
class CapturedStdout {
  public:
    explicit CapturedStdout(const std::string &name) {
        std::fflush(stdout);
        path_ = std::string(::testing::TempDir()) + "cli-out-" + name + ".txt";
        original_ = stdout;
        stdout = std::fopen(path_.c_str(), "w");
    }
    ~CapturedStdout() {
        std::fflush(stdout);
        std::fclose(stdout);
        stdout = original_;
    }
    CapturedStdout(const CapturedStdout &) = delete;
    auto operator=(const CapturedStdout &) -> CapturedStdout & = delete;

    [[nodiscard]] auto content() const -> std::string {
        // stdout is fully buffered while redirected to a file: flush so
        // reads inside the capture scope see what runCli has printed.
        std::fflush(stdout);
        std::ifstream input(path_, std::ios::binary);
        return {std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>()};
    }

  private:
    FILE *original_ = nullptr;
    std::string path_;
};

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - (name, body) is the
// same shape every config-writing helper in this suite uses.
auto writeTempConfig(const std::string &name, const std::string &dataDir)
    -> std::string {
    const auto path = std::filesystem::path(::testing::TempDir()) /
                      ("linko-cli-" + name + ".json");
    std::ofstream output(path);
    output << R"({"dataDir": ")" + dataDir + R"(", "port": 443})";
    output.close();
    return path.string();
}

auto readFileBytes(const std::string &path) -> std::string {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

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

// Extracts the trailing code= parameter of the printed join link.
auto codeFromLink(const std::string &output) -> std::string {
    const auto marker = output.find("&code=");
    if (marker == std::string::npos) {
        return {};
    }
    const auto start = marker + std::strlen("&code=");
    const auto end = output.find('\n', start);
    return output.substr(start, end - start);
}

// Temp data dir + config + ephemeral certificate for one CLI test.
struct CliFixture {
    std::string dataDir;
    std::string configPath;
    std::string certPath;
    std::string keyPath;

    explicit CliFixture(const std::string &name)
        : dataDir(std::string(::testing::TempDir()) + "linko-cli-" + name),
          configPath(writeTempConfig(name, dataDir)) {
        std::filesystem::create_directories(dataDir);
        // Temp dirs survive across runs: drop any previous database first.
        for (const auto *const suffix : {"", "-wal", "-shm"}) {
            std::error_code ignored;
            std::filesystem::remove(dataDir + "/linko.db" + suffix, ignored);
        }
        const auto paths = test_util::makeEphemeralCert(name);
        certPath = paths.first;
        keyPath = paths.second;
    }

    [[nodiscard]] auto dbPath() const -> std::string {
        return dataDir + "/linko.db";
    }
};

// Raw database bytes including the WAL sidecar (the last write may still
// live there).
auto dbBytesIncludingWal(const std::string &dbPath) -> std::string {
    return readFileBytes(dbPath) + readFileBytes(dbPath + "-wal");
}

auto systemNowMs() -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

TEST(Cli, UnknownCommandExits2) {
    EXPECT_EQ(runCli({"bogus"}), 2);
    EXPECT_EQ(runCli({}), 2);
    EXPECT_EQ(runCli({"--config"}), 2);
}

TEST(Cli, InviteCreatePrintsLinkAndQr) {
    const CliFixture fixture("invite-link");
    CapturedStdout capture("invite-link");
    EXPECT_EQ(
        runCli({"--config", fixture.configPath, "invite", "create", "--host",
                "qrtest.example", "--port", "443", "--cert", fixture.certPath}),
        0);
    const auto output = capture.content();
    EXPECT_NE(output.find("linko://join?host=qrtest.example&port=443&pin="),
              std::string::npos)
        << output;
    EXPECT_NE(output.find("&code="), std::string::npos);
    EXPECT_NE(output.find(kQrBlock), std::string::npos)
        << "expected a terminal QR code in the output";
}

TEST(Cli, InviteCreateStoresHashOnly) {
    const CliFixture fixture("invite-hash");
    {
        CapturedStdout capture("invite-hash");
        EXPECT_EQ(runCli({"--config", fixture.configPath, "invite", "create",
                          "--host", "h", "--port", "443", "--cert",
                          fixture.certPath}),
                  0);
        const auto code = codeFromLink(capture.content());
        ASSERT_FALSE(code.empty());
        const auto raw = dbBytesIncludingWal(fixture.dbPath());
        EXPECT_EQ(raw.find(code), std::string::npos)
            << "the plaintext invite code must never reach the database";
        EXPECT_NE(raw.find(linko::sha256Hex(
                      std::vector<std::uint8_t>(code.begin(), code.end()))),
                  std::string::npos);
    }
}

TEST(Cli, InviteTtlFlagExpires) {
    const CliFixture fixture("invite-ttl");
    {
        CapturedStdout capture("invite-ttl");
        EXPECT_EQ(runCli({"--config", fixture.configPath, "invite", "create",
                          "--ttl-hours", "2"}),
                  0);
        const auto code = codeFromLink(capture.content());
        ASSERT_FALSE(code.empty());

        // A clock two hours and one minute past creation must see the invite
        // expired - with the 24-hour default it would still be valid there.
        server::Store store(
            fixture.dbPath(), []() -> std::string { return "unused"; },
            []() -> std::int64_t {
                return systemNowMs() + kTtlHoursMs + kPastTtlMs;
            });
        EXPECT_EQ(store.consumeInvite(code, "someone"),
                  server::InviteResult::Expired);
    }
}

TEST(Cli, UserListPrintsUsers) {
    const CliFixture fixture("user-list");
    {
        server::Store store(fixture.dbPath(),
                            []() -> std::string { return "unused"; });
        store.migrate();
        static_cast<void>(
            store.registerDevice("anna", "hash-a1", systemNowMs()));
    }
    CapturedStdout capture("user-list");
    EXPECT_EQ(runCli({"--config", fixture.configPath, "user", "list"}), 0);
    EXPECT_NE(capture.content().find("anna"), std::string::npos);
}

// Populates a store with two devices of one user: the first (older) one is
// already revoked by re-registration, the second one is active.
auto populateTwoDevices(const std::string &dbPath) -> std::int64_t {
    server::Store store(dbPath, []() -> std::string { return "unused"; });
    store.migrate();
    const auto now = systemNowMs();
    static_cast<void>(store.registerDevice("eugene", "hash-e1", now));
    static_cast<void>(store.registerDevice("eugene", "hash-e2", now + 1));
    const auto devices = store.listDevices("eugene");
    EXPECT_EQ(devices.size(), 2U);
    EXPECT_TRUE(devices[0].revoked);
    EXPECT_FALSE(devices[1].revoked);
    return devices[1].id;
}

TEST(Cli, DeviceListShowsRevokedAndActive) {
    const CliFixture fixture("device-list");
    const auto activeId = populateTwoDevices(fixture.dbPath());

    CapturedStdout capture("device-list");
    EXPECT_EQ(
        runCli({"--config", fixture.configPath, "device", "list", "eugene"}),
        0);
    const auto output = capture.content();
    EXPECT_NE(output.find(std::to_string(activeId) + " active"),
              std::string::npos)
        << output;
}

TEST(Cli, DeviceRevokeMarksRevoked) {
    const CliFixture fixture("device-revoke");
    const auto activeId = populateTwoDevices(fixture.dbPath());

    CapturedStdout capture("device-revoke");
    EXPECT_EQ(runCli({"--config", fixture.configPath, "device", "revoke",
                      "eugene", std::to_string(activeId)}),
              0);
    EXPECT_NE(capture.content().find("revoked"), std::string::npos);

    server::Store store(fixture.dbPath(),
                        []() -> std::string { return "unused"; });
    EXPECT_FALSE(store.deviceByTokenHash("hash-e2").has_value());
}

TEST(Cli, DeviceRevokeBadIdExits2) {
    const CliFixture fixture("device-bad");
    CapturedStdout capture("device-bad");
    EXPECT_EQ(runCli({"--config", fixture.configPath, "device", "revoke",
                      "eugene", "notanumber"}),
              2);
}
