// Call registry integration tests (Plan 3 Task 6): the full server stack
// (TLS listener, websocket sessions, hub, call registry) on an ephemeral
// port; sync Beast WebSocket clients play alice (caller), bob (callee) and
// carol (a third user). The injected clock drives the ring/connect timers,
// which poll every 100 ms against it - no sleeps in the tests.
#include <cstdint>
#include <filesystem>
#include <functional>
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

#include "linko/call_state_machine.hpp"
#include "linko/messages.hpp"
#include "linko/sha256.hpp"
#include "server/call_registry.hpp"
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

// The database path for a test, with any previous files removed first (the
// fixture's Store must open a fresh file; deleting it after opening would
// break the connection).
auto freshRegistryDbPath(const std::string &name) -> std::string {
    const auto dbPath =
        std::string(::testing::TempDir()) + "linko-registry-" + name + ".db";
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

    auto close(unsigned short code) -> void {
        boost::system::error_code ignored;
        stream_->close(websocket::close_reason(code), ignored);
    }

  private:
    asio::io_context io_;
    ssl::context ctx_;
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> stream_;
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

// The full server stack with the call registry wired as the call sink.
class RegistryFixture {
  public:
    explicit RegistryFixture(const std::string &name)
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshRegistryDbPath(name)), clock_(), io_(),
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
    [[nodiscard]] auto clock() -> FakeClock & { return clock_; }

  private:
    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    FakeClock clock_;
    server::Limits limits_;
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

auto parseJson(const std::string &text) -> nlohmann::json {
    return nlohmann::json::parse(text, nullptr, false);
}

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

// Frame matcher: top-level type equals `type` and, when the frame carries a
// body object, its callId equals `callId`.
class CallIs {
  public:
    CallIs(std::string_view type, std::string callId)
        : type_(type), callId_(std::move(callId)) {}

    auto operator()(const nlohmann::json &frame) const -> bool {
        return frame.value("type", "") == type_ && frame.contains("body") &&
               frame["body"].value("callId", "") == callId_;
    }

  private:
    std::string_view type_;
    std::string callId_;
};

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

} // namespace

TEST(CallRegistry, InviteRoutedToCallee) {
    RegistryFixture fixture("invite");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    const auto wire = waitFor(bob, CallIs{"call.invite", "call-1"});
    ASSERT_FALSE(wire.empty());
    const auto frame = parseJson(wire);
    EXPECT_EQ(frame["body"].value("to", ""), "bob");
    EXPECT_EQ(frame["body"].value("media", ""), "audio");
}

TEST(CallRegistry, RingingAcceptReachCaller) {
    RegistryFixture fixture("ringing-accept");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());

    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallRinging, linko::CallRef{"call-1"}.toBody())));
    ASSERT_FALSE(waitFor(alice, CallIs{"call.ringing", "call-1"}).empty());

    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAccept, linko::CallRef{"call-1"}.toBody())));
    ASSERT_FALSE(waitFor(alice, CallIs{"call.accept", "call-1"}).empty());
}

TEST(CallRegistry, DuplicateAcceptForwardedOnce) {
    RegistryFixture fixture("duplicate-accept");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAccept, linko::CallRef{"call-1"}.toBody())));
    ASSERT_FALSE(waitFor(alice, CallIs{"call.accept", "call-1"}).empty());

    // A second accept is dropped by the machine in Connecting; the very
    // next frame alice sees must be bob's answer, not the duplicate.
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAccept, linko::CallRef{"call-1"}.toBody())));
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAnswer, linko::CallSdp{"call-1", "v=0"}.toBody())));
    const auto next = parseJson(alice.receive());
    EXPECT_EQ(next.value("type", ""), "call.answer");
}

TEST(CallRegistry, NoGlareOnCallerSide) {
    RegistryFixture fixture("no-glare");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());
    ASSERT_FALSE(waitFor(alice, PresenceOf{"bob", true}).empty());

    // Crossed invites: the registry busy-rejects the second invite (alice
    // is in a live call) instead of feeding a glare invite into alice's
    // machine.
    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-2", "alice", "audio"}.toBody())));
    const auto busy = waitFor(bob, CallIs{"call.busy", "call-2"});
    ASSERT_FALSE(busy.empty());
    EXPECT_EQ(parseJson(busy)["body"].value("callId", ""), "call-2");

    // Alice never saw the glare: no forwarded invite and no busy of her
    // own - the next frame she receives is bob's accept for the surviving
    // call.
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAccept, linko::CallRef{"call-1"}.toBody())));
    const auto next = parseJson(alice.receive());
    EXPECT_EQ(next.value("type", ""), "call.accept");
    EXPECT_EQ(next["body"].value("callId", ""), "call-1");
}

TEST(CallRegistry, BusyRejectedWhenCalleeInCall) {
    RegistryFixture fixture("busy");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    registerToken(fixture.store(), "carol", "token-carol");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());
    WsClient carol("token-carol", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());

    // Bob is in a live call: carol's invite is answered with call.busy
    // carrying carol's own callId, and nothing reaches bob.
    carol.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-2", "bob", "video"}.toBody())));
    const auto busy = waitFor(carol, CallIs{"call.busy", "call-2"});
    ASSERT_FALSE(busy.empty());
    EXPECT_EQ(parseJson(busy)["body"].value("callId", ""), "call-2");

    // Bob's next frame is the relayed offer from alice's call, not a second
    // invite - carol's invite never left the registry.
    alice.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallOffer, linko::CallSdp{"call-1", "v=0"}.toBody())));
    const auto next = parseJson(bob.receive());
    EXPECT_EQ(next.value("type", ""), "call.offer");
    EXPECT_EQ(next["body"].value("callId", ""), "call-1");
}

TEST(CallRegistry, RingTimeoutSendsCancelAndCleansUp) {
    RegistryFixture fixture("ring-timeout");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());

    // Moving the injected clock past the ring deadline makes the registry's
    // next 100 ms poll end the call and send a server-built call.cancel to
    // the callee (whose own machine reports Missed without messaging).
    fixture.clock().advance(linko::kRingTimeoutMs + 1);
    const auto cancel = waitFor(bob, CallIs{"call.cancel", "call-1"});
    ASSERT_FALSE(cancel.empty());

    // The entry is gone: a fresh invite with a new callId reaches bob
    // instead of being answered with a stale busy.
    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-2", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-2"}).empty());
}

TEST(CallRegistry, SocketDropEndsCallsAndNotifiesPeer) {
    RegistryFixture fixture("socket-drop");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    registerToken(fixture.store(), "carol", "token-carol");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());

    // Alice's socket drops mid-ring: the registry ends her call (even
    // though the machine in OutgoingRinging ignores RemoteHangup) and sends
    // a server-built call.hangup to the peer.
    alice.close(server::kWsCloseNormal);
    const auto hangup = waitFor(bob, CallIs{"call.hangup", "call-1"});
    ASSERT_FALSE(hangup.empty());
    EXPECT_EQ(parseJson(hangup)["body"].value("callId", ""), "call-1");

    // Alice's entry is erased: carol may invite bob right away.
    WsClient carol("token-carol", fixture.port());
    carol.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-2", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-2"}).empty());
}

TEST(CallRegistry, LateHangupAfterEndedIgnored) {
    RegistryFixture fixture("late-hangup");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallReject,
                     linko::CallEnd{"call-1", std::nullopt}.toBody())));
    ASSERT_FALSE(waitFor(alice, CallIs{"call.reject", "call-1"}).empty());

    // Everything about the ended call is now dropped: the late hangup, then
    // a pass-through offer for the dead callId. The next frame alice sees
    // is the relayed offer of the NEW call - if the late hangup had been
    // forwarded it would have arrived before it.
    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-2", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-2"}).empty());
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallHangup,
                     linko::CallEnd{"call-1", std::nullopt}.toBody())));
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallOffer, linko::CallSdp{"call-2", "v=0"}.toBody())));
    const auto next = parseJson(alice.receive());
    EXPECT_EQ(next.value("type", ""), "call.offer");
    EXPECT_EQ(next["body"].value("callId", ""), "call-2");
}

TEST(CallRegistry, SdpAndFileMessagesForwardedByteIdentical) {
    RegistryFixture fixture("passthrough");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    ASSERT_FALSE(waitFor(bob, CallIs{"call.invite", "call-1"}).empty());
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAccept, linko::CallRef{"call-1"}.toBody())));
    ASSERT_FALSE(waitFor(alice, CallIs{"call.accept", "call-1"}).empty());

    // The offer rides to bob unchanged: the relay re-serializes the parsed
    // envelope, so the canonical bytes are identical.
    const auto offer = wireEnvelope(
        linko::kTypeCallOffer,
        linko::CallSdp{"call-1", "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF"}
            .toBody());
    const auto offerWire = linko::serialize(offer);
    alice.sendText(offerWire);
    EXPECT_EQ(waitFor(bob, CallIs{"call.offer", "call-1"}), offerWire);

    // file.* rides the same relay without machine input (the size cap
    // lands with Task 8): bob's file.offer reaches alice byte-identical.
    const auto fileOffer =
        wireEnvelope(linko::kTypeFileOffer, {
                                                {"callId", "call-1"},
                                                {"fileId", "f-1"},
                                                {"name", "notes.bin"},
                                                {"size", 1024},
                                                {"sha256", "ab12cd34"},
                                                {"chunkSize", 16384},
                                                {"chunkCount", 1},
                                            });
    const auto fileWire = linko::serialize(fileOffer);
    bob.sendText(fileWire);
    EXPECT_EQ(waitFor(alice, CallIs{"file.offer", "call-1"}), fileWire);
}

TEST(CallRegistry, EventsForUnknownCallIgnored) {
    RegistryFixture fixture("unknown-call");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());
    // The hub's attach broadcast carries the newcomer's own presence.
    ASSERT_FALSE(waitFor(bob, PresenceOf{"bob", true}).empty());

    // A burst of traffic for a call the registry never saw: lifecycle
    // messages and a pass-through. None of it produces an error frame or a
    // relay - bob's very next frame is alice's fresh invite.
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallRinging, linko::CallRef{"ghost"}.toBody())));
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallAccept, linko::CallRef{"ghost"}.toBody())));
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallReject,
                     linko::CallEnd{"ghost", std::nullopt}.toBody())));
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallBusy, linko::CallEnd{"ghost", std::nullopt}.toBody())));
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallCancel,
                     linko::CallEnd{"ghost", std::nullopt}.toBody())));
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallHangup,
                     linko::CallEnd{"ghost", std::nullopt}.toBody())));
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallOffer, linko::CallSdp{"ghost", "v=0"}.toBody())));
    bob.sendText(linko::serialize(
        wireEnvelope(linko::kTypeFileOffer, {{"callId", "ghost"}})));

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeCallInvite,
                     linko::CallInvite{"call-1", "bob", "audio"}.toBody())));
    const auto next = parseJson(bob.receive());
    EXPECT_EQ(next.value("type", ""), "call.invite");
    EXPECT_EQ(next["body"].value("callId", ""), "call-1");

    // The registry is healthy: the real call's ringing reaches alice.
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeCallRinging, linko::CallRef{"call-1"}.toBody())));
    ASSERT_FALSE(waitFor(alice, CallIs{"call.ringing", "call-1"}).empty());
}
