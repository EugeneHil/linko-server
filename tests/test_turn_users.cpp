// Authenticated HTTP endpoints (Plan 3 Task 5): users prefix search and
// TURN REST credentials. The credential is recomputed in the test from the
// configured secret; the env-override test proves LINKO_TURN_SECRET wins.
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "linko/sha256.hpp"
#include "server/http.hpp"
#include "server/store.hpp"
#include "util/test_cert.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
using asio::ip::tcp;

namespace {

constexpr std::int64_t kBaseMs = 1790000000000;
constexpr int kTurnTtlSec = 3600;
constexpr int kHttpVersion11 = 11;
constexpr int kHmacDigestBufferBytes = 64;

class ScopedEnv {
  public:
    ScopedEnv(const char *name, const char *value) : name_(name) {
#ifdef _WIN32
        ::_putenv_s(name, value);
#else
        ::setenv(name, value, 1);
#endif
    }
    ~ScopedEnv() {
#ifdef _WIN32
        ::_putenv_s(name_.c_str(), "");
#else
        ::unsetenv(name_.c_str());
#endif
    }
    ScopedEnv(const ScopedEnv &) = delete;
    auto operator=(const ScopedEnv &) -> ScopedEnv & = delete;

  private:
    std::string name_;
};

// base64(HMAC-SHA1(secret, username)) - an independent computation of what
// handleTurn must produce.
auto expectedCredential(const std::string &secret, const std::string &username)
    -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;
    static_cast<void>(
        HMAC(EVP_sha1(), secret.data(), static_cast<int>(secret.size()),
             reinterpret_cast<const unsigned char *>(username.data()),
             static_cast<int>(username.size()), digest.data(), &digestLength));
    std::array<unsigned char, kHmacDigestBufferBytes> encoded{};
    const int encodedLength = EVP_EncodeBlock(encoded.data(), digest.data(),
                                              static_cast<int>(digestLength));
    return {reinterpret_cast<const char *>(encoded.data()),
            static_cast<std::size_t>(encodedLength)};
}

// The database path for a test, with any previous files removed first (the
// fixture's Store must open a fresh file; deleting it after opening would
// break the connection).
auto freshDbPath(const std::string &name) -> std::string {
    const auto dbPath =
        std::string(::testing::TempDir()) + "linko-tu-" + name + ".db";
    for (const auto *const suffix : {"", "-wal", "-shm"}) {
        std::error_code ignored;
        std::filesystem::remove(dbPath + suffix, ignored);
    }
    return dbPath;
}

// Fixture: config loaded from a temp file (turn secret via file or env),
// store on a temp db, users/turn routes on a TLS listener.
class TurnUsersFixture {
  public:
    explicit TurnUsersFixture(const std::string &name,
                              const std::string &fileTurnSecret = "")
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshDbPath(name)),
          store_(std::make_unique<server::Store>(
              dbPath_, []() -> std::string { return "TESTCODE"; },
              []() -> std::int64_t { return kBaseMs; })) {
        configPath_ = writeConfig(name, fileTurnSecret);
        config_ = server::loadConfig(configPath_);
        sslContext_.use_certificate_chain_file(paths_.first);
        sslContext_.use_private_key_file(paths_.second, ssl::context::pem);
        store_->migrate();

        router_.add(
            "GET", "/api/v1/users",
            [this](const server::HttpRequest &request) -> server::HttpResponse {
                return server::handleUsers(*store_, request);
            });
        router_.add(
            "GET", "/api/v1/turn",
            [this](const server::HttpRequest &request) -> server::HttpResponse {
                return server::handleTurn(config_, *store_, request);
            });
        listener_ =
            std::make_unique<server::Listener>(io_, sslContext_, router_);
        listener_->listen("127.0.0.1", 0);
        ioThread_ = std::thread([this]() -> void { io_.run(); });
    }

    ~TurnUsersFixture() {
        io_.stop();
        ioThread_.join();
    }
    TurnUsersFixture(const TurnUsersFixture &) = delete;
    auto operator=(const TurnUsersFixture &) -> TurnUsersFixture & = delete;

    [[nodiscard]] auto port() const -> unsigned short {
        return listener_->port();
    }

    // A device token for `user` and its bearer header, via the store.
    void seedUser(
        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        const std::string &user, const std::string &token) {
        const auto tokenHash = linko::sha256Hex(
            std::vector<std::uint8_t>(token.begin(), token.end()));
        static_cast<void>(store_->registerDevice(user, tokenHash, kBaseMs));
    }

  private:
    static auto writeConfig(const std::string &name,
                            const std::string &fileTurnSecret) -> std::string {
        const auto path = std::filesystem::path(::testing::TempDir()) /
                          ("linko-tu-" + name + ".json");
        std::ofstream output(path);
        // nlohmann serializes the path with proper JSON escaping - a raw
        // interpolation breaks on Windows, where the temp path contains
        // backslashes ("C:\Users\..." is an invalid JSON escape).
        nlohmann::json config = {
            {"dataDir", std::string(::testing::TempDir()) + "linko-tu-data"},
            {"port", 443}};
        if (!fileTurnSecret.empty()) {
            config["turnSecret"] = fileTurnSecret;
        }
        config["limits"] = {{"turnTtlSec", kTurnTtlSec}};
        output << config.dump();
        output.close();
        return path.string();
    }

    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    std::string configPath_;
    server::Config config_;
    std::unique_ptr<server::Store> store_;
    asio::io_context io_;
    ssl::context sslContext_{ssl::context::tls_server};
    server::Router router_;
    std::unique_ptr<server::Listener> listener_;
    std::thread ioThread_;
};

// A minimal HTTPS GET client (same shape as test_http.cpp's helper).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto httpsGet(
    const std::string &host, unsigned short port,
    const std::string &target, // NOLINT(bugprone-easily-swappable-parameters)
    const std::string &authorization = "") -> std::pair<int, std::string> {
    asio::io_context clientIo;
    ssl::context clientContext{ssl::context::tls_client};
    clientContext.set_verify_mode(ssl::verify_none);
    ssl::stream<tcp::socket> stream{clientIo, clientContext};
    tcp::resolver resolver{clientIo};
    const auto endpoints = resolver.resolve(host, std::to_string(port));
    asio::connect(stream.next_layer(), endpoints);
    stream.handshake(ssl::stream_base::client);

    http::request<http::string_body> request{http::verb::get, target,
                                             kHttpVersion11};
    if (!authorization.empty()) {
        request.set(http::field::authorization, authorization);
    }
    request.prepare_payload();
    http::write(stream, request);

    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return {static_cast<int>(response.result_int()), response.body()};
}

auto parseJson(const std::string &text) -> nlohmann::json {
    return nlohmann::json::parse(text, nullptr, false);
}

} // namespace

TEST(TurnUsers, UsersPrefixSearch) {
    TurnUsersFixture fixture("users");
    fixture.seedUser("anna", "token-anna");
    fixture.seedUser("eugene", "token-eugene");
    const std::string bearer = "Bearer token-anna";

    const auto [allStatus, allBody] =
        httpsGet("127.0.0.1", fixture.port(), "/api/v1/users", bearer);
    EXPECT_EQ(allStatus, 200);
    const auto all = parseJson(allBody);
    EXPECT_EQ(all.value("users", nlohmann::json::array()).size(), 2U);

    const auto [prefixStatus, prefixBody] =
        httpsGet("127.0.0.1", fixture.port(), "/api/v1/users?prefix=e", bearer);
    EXPECT_EQ(prefixStatus, 200);
    const auto prefix = parseJson(prefixBody);
    const auto users = prefix.value("users", nlohmann::json::array());
    ASSERT_EQ(users.size(), 1U);
    EXPECT_EQ(users[0], "eugene");
}

TEST(TurnUsers, UsersRequiresAuth) {
    TurnUsersFixture fixture("users-auth");
    fixture.seedUser("anna", "token-anna");
    const auto [noAuthStatus, noAuthBody] =
        httpsGet("127.0.0.1", fixture.port(), "/api/v1/users");
    EXPECT_EQ(noAuthStatus, 401) << noAuthBody;
    const auto [badAuthStatus, badAuthBody] =
        httpsGet("127.0.0.1", fixture.port(), "/api/v1/users", "Bearer wrong");
    EXPECT_EQ(badAuthStatus, 401) << badAuthBody;
}

TEST(TurnUsers, TurnCredentialVerifies) {
    TurnUsersFixture fixture("turn", "file-secret");
    fixture.seedUser("anna", "token-anna");
    const auto [status, body] = httpsGet("127.0.0.1", fixture.port(),
                                         "/api/v1/turn", "Bearer token-anna");
    EXPECT_EQ(status, 200) << body;
    const auto parsed = parseJson(body);
    const auto username = parsed.value("username", "");
    const auto credential = parsed.value("credential", "");
    ASSERT_NE(username.find(":anna"), std::string::npos) << username;
    EXPECT_EQ(parsed.value("ttlSec", 0), kTurnTtlSec);
    EXPECT_EQ(credential, expectedCredential("file-secret", username));
}

TEST(TurnUsers, TurnSecretFromEnv) {
    const ScopedEnv env("LINKO_TURN_SECRET", "env-secret");
    TurnUsersFixture fixture("turn-env");
    fixture.seedUser("anna", "token-anna");
    const auto [status, body] = httpsGet("127.0.0.1", fixture.port(),
                                         "/api/v1/turn", "Bearer token-anna");
    EXPECT_EQ(status, 200) << body;
    const auto parsed = parseJson(body);
    const auto username = parsed.value("username", "");
    // The env secret wins over the (absent) file secret.
    EXPECT_EQ(parsed.value("credential", ""),
              expectedCredential("env-secret", username));
}

TEST(TurnUsers, TurnRequiresAuth) {
    TurnUsersFixture fixture("turn-auth", "file-secret");
    const auto [status, body] =
        httpsGet("127.0.0.1", fixture.port(), "/api/v1/turn");
    EXPECT_EQ(status, 401) << body;
}
