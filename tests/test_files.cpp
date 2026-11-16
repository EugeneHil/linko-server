// File storage tests (Plan 3 Task 8): the HTTPS upload/download surface
// runs against a real TLS listener on 127.0.0.1 with an ephemeral port and
// an ephemeral certificate (sync Beast client helpers in this file); the
// store, the cleanup and the file.offer cap are driven directly. The
// injected clock drives the TTL semantics, so no test sleeps.
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <nlohmann/json.hpp>

#include "linko/envelope.hpp"
#include "linko/file_transfer.hpp"
#include "linko/messages.hpp"
#include "linko/sha256.hpp"
#include "server/call_registry.hpp"
#include "server/file_store.hpp"
#include "server/http.hpp"
#include "server/hub.hpp"
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
constexpr std::int64_t kHourMs = 3600LL * kSecondMs;
constexpr std::int64_t kDayMs = 24LL * 60 * 60 * kSecondMs;
constexpr int kHttpVersion11 = 11;
constexpr std::size_t kRoundtripBytes = 1024UL * 1024UL;
constexpr std::size_t kUploadIdHexChars = 32;
constexpr std::int64_t kTryReceiveTimeoutMs = 200;
constexpr int kClientTimeoutMs = 5000;
// The tiny limits the cap/quota tests shrink the server to (the default
// 100 MiB / 1 GiB are far too big to probe with in-memory payloads).
constexpr std::int64_t kTinyMaxFileBytes = 1024;
constexpr std::int64_t kTinyUserQuotaBytes = 1024;
// The roundtrip payload's byte pattern modulus (a prime, so the bytes do
// not repeat within a power-of-two window).
constexpr std::size_t kPayloadModulus = 251;
// Per-frame bound for the websocket clients: asio SSL sync reads ignore
// socket receive timeouts (they spin on EAGAIN), so every frame read is an
// async read bounded by a timer instead.
constexpr int kWaitFrameTimeoutMs = 2000;

// Bounds a sync socket operation (send and receive alike): a server that
// stops reading a large body must not hang the test client forever.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto setSocketTimeouts(tcp::socket &socket, int timeoutMs) -> void {
#ifdef _WIN32
    const DWORD timeout = static_cast<DWORD>(timeoutMs);
    ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char *>(&timeout), sizeof(timeout));
    ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char *>(&timeout), sizeof(timeout));
#else
    const ::timeval timeout{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    static_cast<void>(::setsockopt(socket.native_handle(), SOL_SOCKET,
                                   SO_RCVTIMEO, &timeout, sizeof(timeout)));
    static_cast<void>(::setsockopt(socket.native_handle(), SOL_SOCKET,
                                   SO_SNDTIMEO, &timeout, sizeof(timeout)));
#endif
}

// The database path for a test, with any previous files removed first (the
// fixture's Store must open a fresh file; deleting it after opening would
// break the connection).
auto freshDbPath(const std::string &name) -> std::string {
    const auto dbPath =
        std::string(::testing::TempDir()) + "linko-files-" + name + ".db";
    for (const auto *const suffix : {"", "-wal", "-shm"}) {
        std::error_code ignored;
        std::filesystem::remove(dbPath + suffix, ignored);
    }
    return dbPath;
}

// The FileStore data directory for a test; TempDir persists across runs, so
// a previous run's files must go.
auto freshDataDir(const std::string &name) -> std::string {
    const auto dataDir =
        std::string(::testing::TempDir()) + "linko-files-dir-" + name;
    std::error_code ignored;
    std::filesystem::remove_all(dataDir, ignored);
    return dataDir;
}

// Fixed clock moved explicitly by the test.
class FakeClock {
  public:
    [[nodiscard]] auto tick() const -> std::int64_t { return nowMs_; }
    void advance(std::int64_t deltaMs) { nowMs_ += deltaMs; }

  private:
    std::int64_t nowMs_ = kBaseMs;
};

// Registers a user through the store directly (the token is its only
// plaintext copy, like the register endpoint would print).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto registerToken(server::Store &store, const std::string &user,
                   const std::string &token) -> void {
    const auto tokenHash =
        linko::sha256Hex(std::vector<std::uint8_t>(token.begin(), token.end()));
    static_cast<void>(store.registerDevice(user, tokenHash, kBaseMs));
}

struct HttpReply {
    int status = 0;
    std::string body;
    std::string linkoSha256; // X-Linko-Sha256 response header, if present
};

// One HTTPS request-response exchange against 127.0.0.1:port. Certificate
// verification is off (the server presents an ephemeral self-signed cert).
// The (host, method, target) order mirrors every call site below. When
// `omitContentLength` is set, the request goes out without a
// Content-Length header (body must be empty) - the 411 probe.
auto httpsRequest(
    const std::string &host, unsigned short port,
    const std::string &method, // NOLINT(bugprone-easily-swappable-parameters)
    const std::string &target, const std::string &body = {},
    const std::string &authorization = {}, bool omitContentLength = false)
    -> HttpReply {
    http::verb verb = http::verb::head;
    if (method == "GET") {
        verb = http::verb::get;
    } else if (method == "POST") {
        verb = http::verb::post;
    } else if (method == "PUT") {
        verb = http::verb::put;
    }
    asio::io_context clientIo;
    ssl::context clientContext{ssl::context::tls_client};
    clientContext.set_verify_mode(ssl::verify_none);
    ssl::stream<tcp::socket> stream{clientIo, clientContext};

    tcp::resolver resolver{clientIo};
    const auto endpoints = resolver.resolve(host, std::to_string(port));
    asio::connect(stream.next_layer(), endpoints);
    setSocketTimeouts(stream.next_layer(), kClientTimeoutMs);
    stream.handshake(ssl::stream_base::client);

    http::request<http::string_body> request{verb, target, kHttpVersion11};
    if (!body.empty()) {
        request.body() = body;
    }
    if (!authorization.empty()) {
        request.set(http::field::authorization, authorization);
    }
    if (!omitContentLength) {
        request.prepare_payload();
    }
    boost::system::error_code writeError;
    http::write(stream, request, writeError);
    if (writeError) {
        return {}; // the server dropped the connection mid-request
    }

    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    boost::system::error_code readError;
    http::read(stream, buffer, response, readError);
    if (readError) {
        return {}; // no response arrived
    }
    HttpReply reply;
    reply.status = static_cast<int>(response.result_int());
    reply.body = response.body();
    const auto sha = response.find("X-Linko-Sha256");
    if (sha != response.end()) {
        reply.linkoSha256 = std::string(sha->value());
    }
    return reply;
}

// Parses the first JSON object in `text` (nlohmann non-throwing parse).
auto parseJson(const std::string &text) -> nlohmann::json {
    return nlohmann::json::parse(text, nullptr, false);
}

// The HTTP surface of the file storage: store + FileStore + router with the
// download prefix route + TLS listener with the upload hooks on an
// ephemeral port, io_context on a helper thread.
class HttpFixture {
  public:
    explicit HttpFixture(const std::string &name, server::Limits limits = {})
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshDbPath(name)), dataDir_(freshDataDir(name)),
          limits_(limits),
          store_(std::make_unique<server::Store>(
              dbPath_, []() -> std::string { return "TESTCODE"; },
              [this]() -> std::int64_t { return clock_.tick(); })),
          files_(std::make_unique<server::FileStore>(dataDir_)) {
        sslContext_.use_certificate_chain_file(paths_.first);
        sslContext_.use_private_key_file(paths_.second, ssl::context::pem);
        store_->migrate();
        router_.addPrefix(
            "GET", "/api/v1/files/",
            [this](const server::HttpRequest &request) -> server::HttpResponse {
                return server::handleFileDownload(*store_, *files_, request);
            });
        uploadHooks_.store = store_.get();
        uploadHooks_.files = files_.get();
        uploadHooks_.limits = limits_;
        uploadHooks_.nowMs = [this]() -> std::int64_t { return clock_.tick(); };
        listener_ = std::make_unique<server::Listener>(
            io_, sslContext_, router_, nullptr, &uploadHooks_);
        listener_->listen("127.0.0.1", 0);
        ioThread_ = std::thread([this]() -> void { io_.run(); });
    }

    ~HttpFixture() {
        io_.stop();
        ioThread_.join();
    }
    HttpFixture(const HttpFixture &) = delete;
    auto operator=(const HttpFixture &) -> HttpFixture & = delete;

    [[nodiscard]] auto port() const -> unsigned short {
        return listener_->port();
    }
    [[nodiscard]] auto store() const -> server::Store & { return *store_; }
    [[nodiscard]] auto clock() -> FakeClock & { return clock_; }

  private:
    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    std::string dataDir_;
    FakeClock clock_;
    server::Limits limits_;
    std::unique_ptr<server::Store> store_;
    std::unique_ptr<server::FileStore> files_;
    asio::io_context io_;
    ssl::context sslContext_{ssl::context::tls_server};
    server::UploadHooks uploadHooks_;
    server::Router router_;
    std::unique_ptr<server::Listener> listener_;
    std::thread ioThread_;
};

// --- the call-registry part: a full WS stack with a small file cap ---

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

    // Reads one message bounded by `timeoutMs`; empty result = the peer
    // closed the connection or nothing arrived in time. The read is async
    // with a timer: asio SSL sync reads would spin on a quiet socket.
    auto receive(int timeoutMs = kWaitFrameTimeoutMs) -> std::string {
        beast::flat_buffer buffer;
        std::string wire;
        asio::steady_timer timer(io_);
        timer.expires_after(std::chrono::milliseconds(timeoutMs));
        stream_->async_read(
            buffer,
            [&timer, &wire, &buffer](boost::system::error_code errorCode,
                                     std::size_t /*bytes*/) -> void {
                static_cast<void>(timer.cancel());
                if (!errorCode) {
                    wire = beast::buffers_to_string(buffer.data());
                }
            });
        timer.async_wait([&](boost::system::error_code errorCode) -> void {
            if (!errorCode) { // fired, not cancelled
                boost::system::error_code ignored;
                // Aborting the pending read: the socket close takes the
                // async op down. The lint matches the POSIX ::close by
                // name; this asio close returns nothing.
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                stream_->next_layer().next_layer().close(ignored);
            }
        });
        io_.restart();
        io_.run();
        return wire;
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

// The full server stack with the call registry wired as the call sink; the
// registry's limits (the file.offer cap) come from the test.
class RegistryFixture {
  public:
    RegistryFixture(const std::string &name, server::Limits limits)
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshDbPath(name)), limits_(limits), clock_(), io_(),
          sslContext_{ssl::context::tls_server},
          store_(std::make_unique<server::Store>(
              dbPath_, []() -> std::string { return "TESTCODE"; },
              [this]() -> std::int64_t { return clock_.tick(); })),
          hub_([this]() -> std::int64_t { return clock_.tick(); }),
          registry_(
              hub_, limits_, [this]() -> std::int64_t { return clock_.tick(); },
              io_.get_executor()) {
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
        hooks_.callSink = &registry_;
        hooks_.msgSink = &msgSink_;
        hooks_.limits = limits_;
        hooks_.nowMs = [this]() -> std::int64_t { return clock_.tick(); };

        listener_ = std::make_unique<server::Listener>(io_, sslContext_,
                                                       router_, &hooks_);
        listener_->listen("127.0.0.1", 0);
        ioThread_ = std::thread([this]() -> void { io_.run(); });
    }

    ~RegistryFixture() {
        io_.stop();
        ioThread_.join();
    }
    RegistryFixture(const RegistryFixture &) = delete;
    auto operator=(const RegistryFixture &) -> RegistryFixture & = delete;

    [[nodiscard]] auto port() const -> unsigned short {
        return listener_->port();
    }
    [[nodiscard]] auto store() const -> server::Store & { return *store_; }

  private:
    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    server::Limits limits_;
    FakeClock clock_;
    // io_ and sslContext_ precede registry_/listener_: the registry is
    // built on io_'s executor and the listener loads the TLS context.
    asio::io_context io_;
    ssl::context sslContext_;
    std::unique_ptr<server::Store> store_;
    server::Hub hub_;
    server::CallRegistry registry_;
    server::NullSink msgSink_;
    server::WsHooks hooks_;
    server::Router router_;
    std::unique_ptr<server::Listener> listener_;
    std::thread ioThread_;
};

// Builds an envelope with a fresh id; only the test thread sends, so a
// counter is enough and the registry never sees a duplicated id.
auto wireEnvelope(std::string_view type, nlohmann::json body)
    -> linko::Envelope {
    static int nextId = 0;
    return {
        linko::kCurrentVersion,
        std::string(type),
        "w" + std::to_string(++nextId),
        kBaseMs,
        std::move(body),
    };
}

// Reads frames until one matches, skipping presence broadcasts; returns the
// raw wire bytes of the match (empty when nothing matched within the
// budget).
auto waitFor(WsClient &client,
             const std::function<bool(const nlohmann::json &)> &match,
             int maxFrames = 16) -> std::string {
    for (int frame = 0; frame < maxFrames; ++frame) {
        const auto wire = client.receive();
        const auto parsed = parseJson(wire);
        if (!parsed.is_discarded() && match(parsed)) {
            return wire;
        }
    }
    return "";
}

// Frame matcher: the presence broadcast of `user` in state `online`.
class PresenceOf {
  public:
    PresenceOf(std::string user, bool online)
        : user_(std::move(user)), online_(online) {}

    auto operator()(const nlohmann::json &frame) const -> bool {
        return frame.value("type", "") == "presence.changed" &&
               frame.contains("body") &&
               frame["body"].value("user", "") == user_ &&
               frame["body"].value("online", !online_) == online_;
    }

  private:
    std::string user_;
    bool online_ = false;
};

// Deterministic patterned bytes (not trivially compressible) for upload
// roundtrips. Kept out of the tests: gtest's assertion macros expand to
// branches, which pushes a test body's cognitive complexity over the lint
// threshold once the payload fill adds its loop.
auto patternedPayload(std::size_t size) -> std::string {
    std::string payload(size, '\0');
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<char>(index % kPayloadModulus);
    }
    return payload;
}

} // namespace

// --- upload/download surface ---

TEST(Files, UploadDownloadRoundtrip) {
    HttpFixture fixture("roundtrip");
    registerToken(fixture.store(), "anna", "token-anna");

    const auto payload = patternedPayload(kRoundtripBytes);
    const auto expectedSha = linko::sha256Hex(
        std::vector<std::uint8_t>(payload.begin(), payload.end()));

    const auto uploaded =
        httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files",
                     payload, "Bearer token-anna");
    ASSERT_EQ(uploaded.status, 201) << uploaded.body;
    const auto parsed = parseJson(uploaded.body);
    ASSERT_FALSE(parsed.is_discarded()) << "body=[" << uploaded.body << "]";
    const auto fileId = parsed.value("fileId", "");
    EXPECT_EQ(parsed.value("sha256", ""), expectedSha);
    EXPECT_EQ(parsed.value("size", std::int64_t{0}),
              static_cast<std::int64_t>(payload.size()));
    EXPECT_EQ(fileId.size(), kUploadIdHexChars);
    EXPECT_EQ(fileId.find_first_not_of("0123456789abcdef"), std::string::npos);

    const auto downloaded =
        httpsRequest("127.0.0.1", fixture.port(), "GET",
                     "/api/v1/files/" + fileId, {}, "Bearer token-anna");
    ASSERT_EQ(downloaded.status, 200) << downloaded.body;
    EXPECT_EQ(downloaded.body, payload);
    EXPECT_EQ(downloaded.linkoSha256, expectedSha);
}

TEST(Files, UploadReturnsSha256AndSize) {
    HttpFixture fixture("sha-size");
    registerToken(fixture.store(), "anna", "token-anna");

    const std::string payload(70000, 'x');
    const auto expectedSha = linko::sha256Hex(
        std::vector<std::uint8_t>(payload.begin(), payload.end()));
    const auto uploaded =
        httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files",
                     payload, "Bearer token-anna");
    ASSERT_EQ(uploaded.status, 201) << uploaded.body;
    const auto parsed = parseJson(uploaded.body);
    ASSERT_FALSE(parsed.is_discarded()) << "body=[" << uploaded.body << "]";
    EXPECT_EQ(parsed.value("sha256", ""), expectedSha);
    EXPECT_EQ(parsed.value("size", std::int64_t{0}),
              static_cast<std::int64_t>(payload.size()));

    // The store row carries the same facts, owned by the uploader.
    const auto row = fixture.store().fileInfo(parsed.value("fileId", ""));
    if (!row.has_value()) {
        FAIL() << "the uploaded file must be tracked in the store";
    }
    EXPECT_EQ(row->owner, "anna");
    EXPECT_EQ(row->size, static_cast<std::int64_t>(payload.size()));
    EXPECT_EQ(row->sha256, expectedSha);
}

TEST(Files, FileOverCapRejected413) {
    server::Limits limits;
    limits.maxFileBytes = kTinyMaxFileBytes;
    HttpFixture fixture("over-cap", limits);
    registerToken(fixture.store(), "anna", "token-anna");

    const std::string payload(2048, 'y');
    const auto reply =
        httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files",
                     payload, "Bearer token-anna");
    EXPECT_EQ(reply.status, 413) << reply.body;
    EXPECT_NE(reply.body.find("file_too_large"), std::string::npos);
    EXPECT_EQ(fixture.store().quotaUsed("anna"), std::uint64_t{0});
}

TEST(Files, UploadWithoutLength411) {
    HttpFixture fixture("no-length");
    registerToken(fixture.store(), "anna", "token-anna");

    const auto reply =
        httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files", {},
                     "Bearer token-anna", true /* omitContentLength */);
    EXPECT_EQ(reply.status, 411) << reply.body;
    EXPECT_NE(reply.body.find("length_required"), std::string::npos);
    EXPECT_EQ(fixture.store().quotaUsed("anna"), std::uint64_t{0});
}

TEST(Files, QuotaExceeded507) {
    server::Limits limits;
    limits.userQuotaBytes = kTinyUserQuotaBytes;
    HttpFixture fixture("quota", limits);
    registerToken(fixture.store(), "anna", "token-anna");

    const std::string chunk(512, 'z');
    ASSERT_EQ(httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files",
                           chunk, "Bearer token-anna")
                  .status,
              201);
    // Filling the quota exactly is still allowed (only *over* is rejected).
    ASSERT_EQ(httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files",
                           chunk, "Bearer token-anna")
                  .status,
              201);
    const auto third =
        httpsRequest("127.0.0.1", fixture.port(), "PUT", "/api/v1/files", chunk,
                     "Bearer token-anna");
    EXPECT_EQ(third.status, 507) << third.body;
    EXPECT_NE(third.body.find("quota_exceeded"), std::string::npos);
}

TEST(Files, GetUnknown404) {
    HttpFixture fixture("get-unknown");
    registerToken(fixture.store(), "anna", "token-anna");

    const auto unknown =
        httpsRequest("127.0.0.1", fixture.port(), "GET",
                     "/api/v1/files/00000000000000000000000000000000", {},
                     "Bearer token-anna");
    EXPECT_EQ(unknown.status, 404) << unknown.body;
    EXPECT_NE(unknown.body.find("not_found"), std::string::npos);
    // A malformed id is also a plain 404 - never a traversal probe.
    const auto malformed = httpsRequest("127.0.0.1", fixture.port(), "GET",
                                        "/api/v1/files/../../../etc/passwd", {},
                                        "Bearer token-anna");
    EXPECT_EQ(malformed.status, 404) << malformed.body;
}

TEST(Files, UploadRequiresAuth) {
    HttpFixture fixture("no-auth");

    const auto reply = httpsRequest("127.0.0.1", fixture.port(), "PUT",
                                    "/api/v1/files", std::string(16, 'q'));
    EXPECT_EQ(reply.status, 401) << reply.body;
    EXPECT_NE(reply.body.find("unauthorized"), std::string::npos);
}

// --- TTL cleanup ---

TEST(FilesCleanup, ExpiredFilesRemoved) {
    const auto dbPath = freshDbPath("cleanup");
    const auto dataDir = freshDataDir("cleanup");
    server::Store store(dbPath);
    store.migrate();
    server::FileStore files(dataDir);

    const std::string idExpired(32, 'a');
    const std::string idFresh(32, 'b');
    // created exactly at the TTL boundary stays; one millisecond later it
    // goes; the fresh file survives every cleanup.
    server::FileRow rowExpired{
        idExpired, "anna", 3, "sha-expired", kBaseMs, files.pathOf(idExpired),
    };
    server::FileRow rowFresh{
        idFresh,
        "anna",
        4,
        "sha-fresh",
        kBaseMs + kHourMs,
        files.pathOf(idFresh),
    };
    store.addFile(rowExpired);
    store.addFile(rowFresh);
    {
        std::ofstream out(files.pathOf(idExpired), std::ios::binary);
        out << "aaa";
    }
    {
        std::ofstream out(files.pathOf(idFresh), std::ios::binary);
        out << "bbbb";
    }

    server::cleanupExpiredFiles(store, files, 1, kBaseMs + kDayMs);
    const auto keptAtBoundary = store.fileInfo(idExpired);
    if (!keptAtBoundary.has_value()) {
        FAIL() << "a file exactly at the TTL boundary must survive";
    }
    EXPECT_TRUE(std::filesystem::exists(files.pathOf(idExpired)));

    server::cleanupExpiredFiles(store, files, 1, kBaseMs + kDayMs + 1);
    EXPECT_FALSE(store.fileInfo(idExpired).has_value());
    EXPECT_FALSE(std::filesystem::exists(files.pathOf(idExpired)));
    const auto kept = store.fileInfo(idFresh);
    if (!kept.has_value()) {
        FAIL() << "the fresh file must survive the cleanup";
    }
    EXPECT_EQ(kept->id, idFresh);
    EXPECT_TRUE(std::filesystem::exists(files.pathOf(idFresh)));
}

// --- file.offer cap in the call registry ---

TEST(FilesRegistry, FileOfferOverCapRejected) {
    server::Limits limits;
    limits.maxFileBytes = kTinyMaxFileBytes;
    RegistryFixture fixture("offer-cap", limits);
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());
    ASSERT_FALSE(waitFor(alice, PresenceOf{"bob", true}).empty());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, [](const nlohmann::json &frame) -> bool {
                     return frame.value("type", "") == "call.invite" &&
                            frame.contains("body") &&
                            frame["body"].value("callId", "") == "call-1";
                 }).empty());

    const auto manifest =
        linko::makeManifest("big.bin", 2048, std::string(64, '0'));
    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeFileOffer,
                     linko::FileOffer{"call-1", "file-1", manifest}.toBody())));

    // The sender gets the rejection; the callee never sees the offer.
    const auto errorWire =
        waitFor(alice, [](const nlohmann::json &frame) -> bool {
            return frame.value("type", "") == "session.error" &&
                   frame.contains("body") &&
                   frame["body"].value("code", "") == "file_too_large";
        });
    ASSERT_FALSE(errorWire.empty()) << "the sender must be told about the cap";
    EXPECT_EQ(bob.receive(kTryReceiveTimeoutMs), "");
}

// --- wire contract pin: the cap closes the Plan-2 chunk-count wrap note ---

TEST(Files, ChunkCountAtCapFitsUint32) {
    const auto manifest = linko::makeManifest(
        "max.bin", static_cast<std::uint64_t>(server::kDefaultMaxFileBytes),
        std::string(64, '0'));
    // 100 MiB in 16 KiB chunks = 6400, far below the uint32 chunk counter.
    EXPECT_EQ(manifest.chunkCount, std::uint32_t{6400});
    EXPECT_LE(manifest.chunkCount, std::numeric_limits<std::uint32_t>::max());
}
