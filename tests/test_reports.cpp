// Call reports (Plan 3 Task 9): POST /api/v1/calls/{callId}/report stores
// the client's end-of-call quality summary verbatim behind Bearer auth, and
// the `calls list|show` CLI prints rows derived from the stored JSON.
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>

#include "linko/sha256.hpp"
#include "server/cli.hpp"
#include "server/http.hpp"
#include "server/store.hpp"
#include "util/captured_stdout.hpp"
#include "util/test_cert.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
using asio::ip::tcp;

namespace {

constexpr std::int64_t kBaseMs = 1790000000000;
constexpr int kHttpVersion11 = 11;
// The report size cap (spec: a JSON object of at most 8 KiB) - the
// boundary test builds a body of exactly this size.
constexpr std::size_t kMaxReportBytes = 8192;

// A report body with every field the CLI's list columns read.
constexpr const char *kFullReport =
    R"({"duration":42,"setupMs":7,"candidate":"relay","endReason":"hangup"})";

// The database path for a test, with any previous files removed first (the
// fixture's Store must open a fresh file; deleting it after opening would
// break the connection).
auto freshDbPath(const std::string &name) -> std::string {
    const auto dbPath =
        std::string(::testing::TempDir()) + "linko-report-" + name + ".db";
    for (const auto *const suffix : {"", "-wal", "-shm"}) {
        std::error_code ignored;
        std::filesystem::remove(dbPath + suffix, ignored);
    }
    return dbPath;
}

// Fixture: store on a temp db, the report route on a TLS listener; the
// clock is frozen so receivedAt values are deterministic.
class ReportsFixture {
  public:
    explicit ReportsFixture(const std::string &name)
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshDbPath(name)),
          store_(std::make_unique<server::Store>(
              dbPath_, []() -> std::string { return "TESTCODE"; },
              []() -> std::int64_t { return kBaseMs; })) {
        sslContext_.use_certificate_chain_file(paths_.first);
        sslContext_.use_private_key_file(paths_.second, ssl::context::pem);
        store_->migrate();
        router_.addPrefix(
            "POST", "/api/v1/calls/",
            [this](const server::HttpRequest &request) -> server::HttpResponse {
                return server::handleCallReport(*store_, request, kBaseMs);
            });
        listener_ =
            std::make_unique<server::Listener>(io_, sslContext_, router_);
        listener_->listen("127.0.0.1", 0);
        ioThread_ = std::thread([this]() -> void { io_.run(); });
    }

    ~ReportsFixture() {
        io_.stop();
        ioThread_.join();
    }
    ReportsFixture(const ReportsFixture &) = delete;
    auto operator=(const ReportsFixture &) -> ReportsFixture & = delete;

    [[nodiscard]] auto port() const -> unsigned short {
        return listener_->port();
    }

    [[nodiscard]] auto store() const -> server::Store & { return *store_; }

    // A device token for `user`, via the store.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void seedUser(const std::string &user, const std::string &token) {
        const auto tokenHash = linko::sha256Hex(
            std::vector<std::uint8_t>(token.begin(), token.end()));
        static_cast<void>(store_->registerDevice(user, tokenHash, kBaseMs));
    }

  private:
    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    std::unique_ptr<server::Store> store_;
    asio::io_context io_;
    ssl::context sslContext_{ssl::context::tls_server};
    server::Router router_;
    std::unique_ptr<server::Listener> listener_;
    std::thread ioThread_;
};

// A minimal HTTPS POST client (same shape as test_turn_users.cpp's helper).
// The diagnostics of the adjacent string parameters point at the first of
// them, so the NOLINT sits inside the parameter list, above `target`.
auto httpsPost(const std::string &host, unsigned short port,
               // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
               const std::string &target, const std::string &authorization,
               const std::string &body) -> std::pair<int, std::string> {
    asio::io_context clientIo;
    ssl::context clientContext{ssl::context::tls_client};
    clientContext.set_verify_mode(ssl::verify_none);
    ssl::stream<tcp::socket> stream{clientIo, clientContext};
    tcp::resolver resolver{clientIo};
    const auto endpoints = resolver.resolve(host, std::to_string(port));
    asio::connect(stream.next_layer(), endpoints);
    stream.handshake(ssl::stream_base::client);

    http::request<http::string_body> request{http::verb::post, target,
                                             kHttpVersion11};
    request.set(http::field::authorization, authorization);
    request.body() = body;
    request.prepare_payload();
    http::write(stream, request);

    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return {static_cast<int>(response.result_int()), response.body()};
}

auto writeTempConfig(
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): (name, dataDir)
    const std::string &name, const std::string &dataDir) -> std::string {
    const auto path = std::filesystem::path(::testing::TempDir()) /
                      ("linko-reports-" + name + ".json");
    std::ofstream output(path);
    // nlohmann serializes the path with proper JSON escaping - a raw
    // interpolation breaks on Windows, where the temp path contains
    // backslashes ("C:\Users\..." is an invalid JSON escape).
    const nlohmann::json config = {{"dataDir", dataDir}, {"port", 443}};
    output << config.dump();
    output.close();
    return path.string();
}

// Temp data dir + config for one CLI test; stale databases are removed
// first (TempDir persists across runs).
struct CliFixture {
    std::string dataDir;
    std::string configPath;

    explicit CliFixture(const std::string &name)
        : dataDir(std::string(::testing::TempDir()) + "linko-reports-cli-" +
                  name),
          configPath(writeTempConfig(name, dataDir)) {
        std::filesystem::create_directories(dataDir);
        for (const auto *const suffix : {"", "-wal", "-shm"}) {
            std::error_code ignored;
            std::filesystem::remove(dataDir + "/linko.db" + suffix, ignored);
        }
    }

    [[nodiscard]] auto dbPath() const -> std::string {
        return dataDir + "/linko.db";
    }
};

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

} // namespace

TEST(Reports, Stored) {
    ReportsFixture fixture("stored");
    fixture.seedUser("anna", "token-anna");
    const auto [status, body] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "Bearer token-anna", kFullReport);
    EXPECT_EQ(status, 204) << body;

    const auto rows = fixture.store().callReports();
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows[0].callId, "call-1");
    EXPECT_EQ(rows[0].fromUser, "anna");
    EXPECT_EQ(rows[0].receivedAt, kBaseMs);
    EXPECT_EQ(rows[0].reportJson, kFullReport);
}

TEST(Reports, RequiresAuth) {
    ReportsFixture fixture("auth");
    fixture.seedUser("anna", "token-anna");
    const auto [noAuthStatus, noAuthBody] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "", kFullReport);
    EXPECT_EQ(noAuthStatus, 401) << noAuthBody;
    const auto [badAuthStatus, badAuthBody] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "Bearer wrong", kFullReport);
    EXPECT_EQ(badAuthStatus, 401) << badAuthBody;
    EXPECT_TRUE(fixture.store().callReports().empty());
}

TEST(Reports, RejectsNonJson) {
    ReportsFixture fixture("non-json");
    fixture.seedUser("anna", "token-anna");
    const auto [textStatus, textStatusBody] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "Bearer token-anna", "not json");
    EXPECT_EQ(textStatus, 400) << textStatusBody;
    // Valid JSON that is not an object is equally unusable.
    const auto [arrayStatus, arrayStatusBody] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "Bearer token-anna", R"([1, 2])");
    EXPECT_EQ(arrayStatus, 400) << arrayStatusBody;
    EXPECT_TRUE(fixture.store().callReports().empty());
}

TEST(Reports, RejectsOversized) {
    ReportsFixture fixture("oversized");
    fixture.seedUser("anna", "token-anna");
    const auto oversized = R"({"pad":")" + std::string(9000, 'a') + R"("})";
    const auto [status, body] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "Bearer token-anna", oversized);
    EXPECT_EQ(status, 400) << body;
    EXPECT_TRUE(fixture.store().callReports().empty());
}

TEST(Reports, BoundaryAccepted) {
    ReportsFixture fixture("boundary");
    fixture.seedUser("anna", "token-anna");
    // A JSON object of exactly the size cap is the largest accepted report.
    const std::string prefix = R"({"pad":")";
    const std::string suffix = R"("})";
    const auto padding = kMaxReportBytes - prefix.size() - suffix.size();
    const auto body = prefix + std::string(padding, 'a') + suffix;
    ASSERT_EQ(body.size(), kMaxReportBytes);
    const auto [status, responseBody] =
        httpsPost("127.0.0.1", fixture.port(), "/api/v1/calls/call-1/report",
                  "Bearer token-anna", body);
    EXPECT_EQ(status, 204) << responseBody;
    EXPECT_EQ(fixture.store().callReports().size(), 1U);
}

TEST(Reports, CliListPrintsRows) {
    const CliFixture fixture("list");
    {
        server::Store store(fixture.dbPath(),
                            []() -> std::string { return "unused"; });
        store.migrate();
        store.addCallReport(
            server::CallReportRow{"call-1", "anna", kBaseMs, kFullReport});
        store.addCallReport(server::CallReportRow{
            "call-2",
            "eugene",
            kBaseMs + 1,
            R"({"duration":15,"setupMs":3,"candidate":"host","endReason":"busy"})",
        });
    }

    int exitCode = -1;
    std::string output;
    {
        test_util::CapturedStdout capture("list");
        exitCode = runCli({"--config", fixture.configPath, "calls", "list"});
        output = capture.content();
    }
    EXPECT_EQ(exitCode, 0);
    // Every column of both rows, pinned as the exact expected lines.
    const auto row1 = "call-1 anna " + std::to_string(kBaseMs) +
                      " duration=42 setupMs=7 candidate=relay "
                      "endReason=hangup";
    const auto row2 = "call-2 eugene " + std::to_string(kBaseMs + 1) +
                      " duration=15 setupMs=3 candidate=host "
                      "endReason=busy";
    EXPECT_NE(output.find(row1), std::string::npos) << output;
    EXPECT_NE(output.find(row2), std::string::npos);
}

TEST(Reports, CliShowPrintsReport) {
    const CliFixture fixture("show");
    {
        server::Store store(fixture.dbPath(),
                            []() -> std::string { return "unused"; });
        store.migrate();
        store.addCallReport(
            server::CallReportRow{"call-1", "anna", kBaseMs, kFullReport});
        store.addCallReport(server::CallReportRow{
            "call-2",
            "eugene",
            kBaseMs + 1,
            R"({"duration":15,"candidate":"host-z9"})",
        });
    }

    int exitCode = -1;
    std::string output;
    {
        test_util::CapturedStdout capture("show");
        exitCode =
            runCli({"--config", fixture.configPath, "calls", "show", "call-1"});
        output = capture.content();
    }
    EXPECT_EQ(exitCode, 0);
    EXPECT_NE(output.find(kFullReport), std::string::npos)
        << "expected the stored report JSON in the output";
    EXPECT_EQ(output.find("host-z9"), std::string::npos)
        << "calls show must not print other calls' reports";
}
