// WebSocket session integration tests (Plan 3 Task 5): real TLS + WebSocket
// upgrade against the listener on an ephemeral port; a sync Beast WebSocket
// client in this file talks to it. Clocks injectable: idle and rate checks
// advance time explicitly, no sleeps (the idle timer polls every 100 ms).
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
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <nlohmann/json.hpp>

#include "linko/messages.hpp"
#include "linko/sha256.hpp"
#include "server/http.hpp"
#include "server/hub.hpp"
#include "server/log.hpp"
#include "server/ws_session.hpp"
#include "util/test_cert.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
using asio::ip::tcp;

namespace {

constexpr std::int64_t kBaseMs = 1790000000000;
constexpr std::int64_t kSecondMs = 1000;
constexpr std::int64_t kIdleTimeoutSec = 1; // fixture override, tiny on purpose
constexpr std::int64_t kIdleAdvanceMs = 5 * kSecondMs;
constexpr std::size_t kOversizeExtraBytes = 1024;
constexpr int kDropPollLimit = 50;
constexpr auto kDropPollQuantum = std::chrono::milliseconds(10);

// The database path for a test, with any previous files removed first (the
// fixture's Store must open a fresh file; deleting it after opening would
// break the connection).
auto freshWsDbPath(const std::string &name) -> std::string {
    const auto dbPath =
        std::string(::testing::TempDir()) + "linko-ws-" + name + ".db";
    for (const auto *const suffix : {"", "-wal", "-shm"}) {
        std::error_code ignored;
        std::filesystem::remove(dbPath + suffix, ignored);
    }
    return dbPath;
}

// Fixed clock moved explicitly by the test.
class FakeClock {
  public:
    [[nodiscard]] auto tick() const -> std::int64_t { return nowMs_; }
    void advance(std::int64_t deltaMs) { nowMs_ += deltaMs; }

  private:
    std::int64_t nowMs_ = kBaseMs;
};

// A sync WebSocket client over TLS with a bearer token. Sync SSL calls need
// no io_context.run().
class WsClient {
  public:
    WsClient(const std::string &token, unsigned short port)
        : io_(), ctx_(ssl::context::tls_client) {
        ctx_.set_verify_mode(ssl::verify_none);
        stream_ = std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(
            io_, ctx_);
        tcp::resolver resolver{io_};
        const auto endpoints =
            resolver.resolve("127.0.0.1", std::to_string(port));
        asio::connect(stream_->next_layer().next_layer(), endpoints);
        // The TLS handshake is explicit even under the websocket stream.
        stream_->next_layer().handshake(ssl::stream_base::client);
        // Beast 1.92 carries extra handshake headers through the decorator
        // option, not through a handshake overload parameter.
        stream_->set_option(websocket::stream_base::decorator(
            [&token](http::request<http::empty_body> &request) -> void {
                request.set(http::field::authorization, "Bearer " + token);
            }));
        stream_->handshake("127.0.0.1", "/ws");
    }

    auto sendText(const std::string &wire) -> void {
        stream_->write(asio::buffer(wire));
    }

    // Reads one message; empty result = the peer closed the connection.
    auto receive() -> std::string {
        beast::flat_buffer buffer;
        boost::system::error_code errorCode;
        stream_->read(buffer, errorCode);
        if (errorCode) {
            return "";
        }
        auto wire = beast::buffers_to_string(buffer.data());
        buffer.consume(buffer.size());
        return wire;
    }

    // The close code observed on the last read (0 when none).
    [[nodiscard]] auto closeCode() const -> int {
        return static_cast<int>(stream_->reason().code);
    }

    auto close(unsigned short code) -> void {
        boost::system::error_code ignored;
        stream_->close(websocket::close_reason(code), ignored);
    }

  private:
    asio::io_context io_;
    ssl::context ctx_;
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> stream_;
};

// Registers a user through the store directly and returns the device token
// (its only plaintext copy, like the register endpoint would print).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto registerDeviceToken(server::Store &store, const std::string &user,
                         const std::string &token) -> void {
    const auto tokenHash =
        linko::sha256Hex(std::vector<std::uint8_t>(token.begin(), token.end()));
    static_cast<void>(store.registerDevice(user, tokenHash, kBaseMs));
}

// The full server stack: store, hub, sinks, listener with WS hooks and
// register/users routes, io_context on a helper thread.
class WsFixture {
  public:
    explicit WsFixture(const std::string &name,
                       server::Limits fixtureLimits = server::Limits{})
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshWsDbPath(name)), limits_(fixtureLimits),
          store_(std::make_unique<server::Store>(
              dbPath_, []() -> std::string { return "TESTCODE"; },
              [this]() -> std::int64_t { return clock_.tick(); })),
          hub_([this]() -> std::int64_t { return clock_.tick(); }) {
        sslContext_.use_certificate_chain_file(paths_.first);
        sslContext_.use_private_key_file(paths_.second, ssl::context::pem);
        store_->migrate();

        hooks_.authenticate = [this](const std::string &authorization)
            -> std::optional<server::Device> {
            server::HttpRequest request;
            request.authorization = authorization;
            return server::authenticateBearer(*store_, request);
        };
        hooks_.hub = &hub_;
        hooks_.callSink = &callSink_;
        hooks_.msgSink = &msgSink_;
        hooks_.limits = limits_;
        hooks_.nowMs = [this]() -> std::int64_t { return clock_.tick(); };

        listener_ = std::make_unique<server::Listener>(io_, sslContext_,
                                                       router_, &hooks_);
        listener_->listen("127.0.0.1", 0);
        ioThread_ = std::thread([this]() -> void { io_.run(); });
    }

    ~WsFixture() {
        io_.stop();
        ioThread_.join();
    }
    WsFixture(const WsFixture &) = delete;
    auto operator=(const WsFixture &) -> WsFixture & = delete;

    [[nodiscard]] auto port() const -> unsigned short {
        return listener_->port();
    }
    [[nodiscard]] auto store() const -> server::Store & { return *store_; }
    [[nodiscard]] auto clock() -> FakeClock & { return clock_; }
    [[nodiscard]] auto dropCount() const -> int { return callSink_.drops; }

  private:
    class CountingSink final : public server::ProtocolSink {
      public:
        int drops = 0;
        void onEnvelope(const std::string & /*fromUser*/,
                        const linko::Envelope & /*envelope*/,
                        std::int64_t /*deviceId*/) override {}
        void onSocketDrop(const std::string & /*user*/) override { ++drops; }
    };

    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    FakeClock clock_;
    server::Limits limits_;
    std::unique_ptr<server::Store> store_;
    server::Hub hub_;
    CountingSink callSink_;
    server::NullSink msgSink_;
    server::WsHooks hooks_;
    asio::io_context io_;
    ssl::context sslContext_{ssl::context::tls_server};
    server::Router router_;
    std::unique_ptr<server::Listener> listener_;
    std::thread ioThread_;
};

auto parseJson(const std::string &text) -> nlohmann::json {
    return nlohmann::json::parse(text, nullptr, false);
}

// The envelope "type" of a wire string; "" when unparseable.
auto wireType(const std::string &wire) -> std::string {
    const auto parsed = linko::parseEnvelope(wire);
    if (!parsed.envelope.has_value()) {
        return "";
    }
    return parsed.envelope->type;
}

} // namespace

TEST(Ws, AuthAndPresenceBroadcast) {
    WsFixture fixture("presence");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    registerDeviceToken(fixture.store(), "eugene", "token-eugene");

    WsClient anna("token-anna", fixture.port());
    WsClient eugene("token-eugene", fixture.port());

    // Anna observes eugene coming online (and herself at attach time).
    bool sawSelfOnline = false;
    bool sawEugeneOnline = false;
    for (int i = 0; i < 4 && !sawEugeneOnline; ++i) {
        const auto wire = anna.receive();
        const auto parsed = parseJson(wire);
        if (parsed.is_discarded()) {
            continue;
        }
        const auto &body = parsed.at("body");
        if (parsed.at("type") == "presence.changed" &&
            body.value("user", "") == "anna" && body.value("online", false)) {
            sawSelfOnline = true;
        }
        if (parsed.at("type") == "presence.changed" &&
            body.value("user", "") == "eugene" && body.value("online", false)) {
            sawEugeneOnline = true;
        }
    }
    EXPECT_TRUE(sawSelfOnline);
    EXPECT_TRUE(sawEugeneOnline);
}

TEST(Ws, BadTokenRejected) {
    WsFixture fixture("bad-token");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    EXPECT_THROW((void)(WsClient("wrong-token", fixture.port())),
                 std::exception);
}

TEST(Ws, RevokedDeviceSocketClosed) {
    WsFixture fixture("revoked");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive()); // own presence

    // Re-registration revokes the first device: its socket closes with 4001.
    registerDeviceToken(fixture.store(), "anna", "token-anna-2");
    WsClient anna2("token-anna-2", fixture.port());
    static_cast<void>(anna2.receive());

    static_cast<void>(anna.receive()); // the close frame: empty read
    EXPECT_EQ(anna.closeCode(), 4001);
}

TEST(Ws, PingGetsPong) {
    WsFixture fixture("ping");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    const auto ping = linko::Envelope{
        linko::kCurrentVersion,
        std::string(linko::kTypeSessionPing),
        "p1",
        kBaseMs,
        nlohmann::json::object(),
    };
    anna.sendText(linko::serialize(ping));
    const auto pong = anna.receive();
    EXPECT_EQ(wireType(pong), std::string(linko::kTypeSessionPong));
}

TEST(Ws, OversizedFrameCloses) {
    WsFixture fixture("oversize");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    const std::string oversized(linko::kMaxEnvelopeBytes + kOversizeExtraBytes,
                                'x');
    anna.sendText(oversized);
    static_cast<void>(anna.receive());
    EXPECT_EQ(anna.closeCode(), 1009);
}

TEST(Ws, RateLimitedConnectionClosed) {
    server::Limits limits;
    limits.envelopesPerMinute = 2;
    WsFixture fixture("rate", limits);
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    const auto ping = linko::Envelope{
        linko::kCurrentVersion,
        std::string(linko::kTypeSessionPing),
        "p",
        kBaseMs,
        nlohmann::json::object(),
    };
    anna.sendText(linko::serialize(ping));
    anna.sendText(linko::serialize(ping));
    anna.sendText(linko::serialize(ping)); // over the budget of 2

    // Two pongs, then the rate_limited error, then the server closes 4002.
    bool sawRateLimited = false;
    for (int i = 0; i < 4 && !sawRateLimited; ++i) {
        const auto wire = anna.receive();
        if (wireType(wire) == std::string(linko::kTypeSessionError)) {
            const auto parsed = parseJson(wire);
            EXPECT_EQ(parsed.at("body").value("code", ""), "rate_limited");
            sawRateLimited = true;
        }
    }
    EXPECT_TRUE(sawRateLimited);
    static_cast<void>(anna.receive()); // the close frame
    EXPECT_EQ(anna.closeCode(), 4002);
}

TEST(Ws, IdleConnectionClosed) {
    server::Limits limits;
    limits.idleTimeoutSec = static_cast<int>(kIdleTimeoutSec);
    WsFixture fixture("idle", limits);
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    // Moving the injected clock past the idle deadline makes the session's
    // next 100 ms idle check close the connection - no sleeps in the test.
    fixture.clock().advance(kIdleAdvanceMs);
    const auto idleError = anna.receive();
    EXPECT_EQ(wireType(idleError), std::string(linko::kTypeSessionError));
    static_cast<void>(anna.receive()); // the close frame
    EXPECT_EQ(anna.closeCode(), 1000);
}

TEST(Ws, UnsupportedVersionGetsErrorAndClose) {
    WsFixture fixture("version");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    const auto versionTwo = linko::Envelope{
        2,
        std::string(linko::kTypeSessionPing),
        "v2",
        kBaseMs,
        nlohmann::json::object(),
    };
    anna.sendText(linko::serialize(versionTwo));
    const auto error = anna.receive();
    EXPECT_EQ(wireType(error), std::string(linko::kTypeSessionError));
    const auto parsed = parseJson(error);
    EXPECT_EQ(parsed.at("body").value("code", ""), "unsupported_version");
    static_cast<void>(anna.receive());
    EXPECT_EQ(anna.closeCode(), 1000);
}

TEST(Ws, MalformedEnvelopeAnsweredWithError) {
    WsFixture fixture("malformed-ws");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    anna.sendText("not json at all");
    const auto error = anna.receive();
    EXPECT_EQ(wireType(error), std::string(linko::kTypeSessionError));
    const auto parsed = parseJson(error);
    EXPECT_EQ(parsed.at("body").value("code", ""), "invalid_envelope");
    // The connection stays open: a follow-up ping still gets a pong.
    const auto ping = linko::Envelope{
        linko::kCurrentVersion,
        std::string(linko::kTypeSessionPing),
        "p",
        kBaseMs,
        nlohmann::json::object(),
    };
    anna.sendText(linko::serialize(ping));
    EXPECT_EQ(wireType(anna.receive()), std::string(linko::kTypeSessionPong));
}

TEST(Ws, HelloMismatchCloses) {
    WsFixture fixture("hello");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    const auto hello = linko::Envelope{
        linko::kCurrentVersion,
        std::string(linko::kTypeSessionHello),
        "h",
        kBaseMs,
        linko::SessionHello{"bob", "device"}.toBody(),
    };
    anna.sendText(linko::serialize(hello));
    const auto error = anna.receive();
    const auto parsed = parseJson(error);
    EXPECT_EQ(parsed.at("body").value("code", ""), "hello_mismatch");
    static_cast<void>(anna.receive());
    EXPECT_EQ(anna.closeCode(), 4003);
}

TEST(Ws, ClientPresenceIgnored) {
    WsFixture fixture("presence-ignore");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    WsClient anna("token-anna", fixture.port());
    static_cast<void>(anna.receive());

    const auto presence = linko::Envelope{
        linko::kCurrentVersion,
        std::string(linko::kTypePresenceChanged),
        "pr",
        kBaseMs,
        linko::PresenceChanged{"bob", true}.toBody(),
    };
    anna.sendText(linko::serialize(presence));
    // Ignored: the next ping is answered normally.
    const auto ping = linko::Envelope{
        linko::kCurrentVersion,
        std::string(linko::kTypeSessionPing),
        "p",
        kBaseMs,
        nlohmann::json::object(),
    };
    anna.sendText(linko::serialize(ping));
    EXPECT_EQ(wireType(anna.receive()), std::string(linko::kTypeSessionPong));
}

TEST(Ws, SocketDropNotifiesSink) {
    WsFixture fixture("drop");
    registerDeviceToken(fixture.store(), "anna", "token-anna");
    {
        WsClient anna("token-anna", fixture.port());
        static_cast<void>(anna.receive());
        anna.close(server::kWsCloseNormal);
    }
    // The drop path runs on the io thread; the idle quantum bounds the wait.
    int attempts = 0;
    while (fixture.dropCount() == 0 && attempts < kDropPollLimit) {
        std::this_thread::sleep_for(kDropPollQuantum);
        ++attempts;
    }
    EXPECT_GT(fixture.dropCount(), 0);
}
