// Messaging integration tests (Plan 3 Task 7): the Store v2 message tables
// directly, then the full server stack (TLS listener, websocket sessions,
// hub, messaging sink) on an ephemeral port with sync Beast WebSocket
// clients. The injected clock drives every timestamp, so assertions are
// exact; drains are bounded by a session.ping probe, so there are no sleeps.
#include <cstdint>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
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
#include "server/messaging.hpp"
#include "server/store.hpp"
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
// Receipt watermarks for the monotonicity assertions.
constexpr std::int64_t kDeliveredUpto = 3;
constexpr std::int64_t kStaleDelivered = 1;
constexpr std::int64_t kReadUpto = 5;

// The database path for a test, with any previous files removed first (the
// fixture's Store must open a fresh file; TempDir persists across runs, so
// stale rows would leak into assertions).
auto freshDbPath(const std::string &prefix, const std::string &name)
    -> std::string {
    const auto dbPath = std::string(::testing::TempDir()) + "linko-" + prefix +
                        "-" + name + ".db";
    for (const auto *const sidecar : {"", "-wal", "-shm"}) {
        std::error_code ignored;
        std::filesystem::remove(dbPath + sidecar, ignored);
    }
    return dbPath;
}

// A store wired to the fixed clock; every store-level test starts from a
// fresh database file. Store is non-copyable, hence the unique_ptr.
auto storeTest(const std::string &name) -> std::unique_ptr<server::Store> {
    auto store = std::make_unique<server::Store>(
        freshDbPath("messaging-store", name),
        []() -> std::string { return "C"; },
        []() -> std::int64_t { return kBaseMs; });
    store->migrate();
    return store;
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

// The full server stack with the messaging sink wired as the msg sink.
class MessagingFixture {
  public:
    explicit MessagingFixture(const std::string &name)
        : paths_(test_util::makeEphemeralCert(name)),
          dbPath_(freshDbPath("messaging", name)), clock_(), io_(),
          sslContext_{ssl::context::tls_server},
          store_(std::make_unique<server::Store>(
              dbPath_, []() -> std::string { return "TESTCODE"; },
              [this]() -> std::int64_t { return clock_.tick(); })),
          hub_([this]() -> std::int64_t { return clock_.tick(); }),
          messaging_(*store_, hub_,
                     [this]() -> std::int64_t { return clock_.tick(); }) {
        sslContext_.use_certificate_chain_file(paths_.first);
        sslContext_.use_private_key_file(paths_.second, ssl::context::pem);
        store_->migrate();

        // Reconnects push the undelivered backlog from the hub's attach path.
        hub_.setConnectHook([this](const std::string &user) -> void {
            messaging_.onConnect(user);
        });

        hooks_.authenticate = [this](const std::string &authorization)
            -> std::optional<server::Device> {
            server::HttpRequest request;
            request.authorization = authorization;
            return server::authenticateBearer(*store_, request);
        };
        hooks_.hub = &hub_;
        hooks_.callSink = &callSink_;
        hooks_.msgSink = &messaging_;
        hooks_.limits = limits_;
        hooks_.nowMs = [this]() -> std::int64_t { return clock_.tick(); };

        listener_ = std::make_unique<server::Listener>(io_, sslContext_,
                                                       router_, &hooks_);
        listener_->listen("127.0.0.1", 0);
        ioThread_ = std::thread([this]() -> void { io_.run(); });
    }

    ~MessagingFixture() {
        io_.stop();
        ioThread_.join();
    }
    MessagingFixture(const MessagingFixture &) = delete;
    auto operator=(const MessagingFixture &) -> MessagingFixture & = delete;

    [[nodiscard]] auto port() const -> unsigned short {
        return listener_->port();
    }
    [[nodiscard]] auto store() const -> server::Store & { return *store_; }

  private:
    std::pair<std::string, std::string> paths_;
    std::string dbPath_;
    FakeClock clock_;
    server::Limits limits_;
    // io_ and sslContext_ precede store_/hub_: the listener loads the TLS
    // context; messaging_ references store_ and hub_.
    asio::io_context io_;
    ssl::context sslContext_;
    std::unique_ptr<server::Store> store_;
    server::Hub hub_;
    server::Messaging messaging_;
    server::NullSink callSink_;
    server::WsHooks hooks_;
    server::Router router_;
    std::unique_ptr<server::Listener> listener_;
    std::thread ioThread_;
};

auto parseJson(const std::string &text) -> nlohmann::json {
    return nlohmann::json::parse(text, nullptr, false);
}

// Builds an envelope with a fresh id; only the test thread sends, so a
// counter is enough and no id ever duplicates.
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

// Frame matchers (the nlohmann value() reads can throw, which tidy's
// exception-escape check flags inside std::function-wrapped lambdas).

// Frame matcher: top-level type equals `name`.
auto typeIs(std::string_view name)
    -> std::function<bool(const nlohmann::json &)> {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    return [name](const nlohmann::json &frame) -> bool {
        return frame.value("type", "") == name;
    };
}

// Frame matcher: the msg.deliver of the message with `msgId`.
auto deliverOf(const std::string &msgId)
    -> std::function<bool(const nlohmann::json &)> {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    return [msgId](const nlohmann::json &frame) -> bool {
        return frame.value("type", "") == linko::kTypeMsgDeliver &&
               frame.contains("body") && frame["body"].contains("message") &&
               frame["body"]["message"].value("id", "") == msgId;
    };
}

// Frame matcher: the msg.stored ack of the message with `msgId`.
auto storedOf(const std::string &msgId)
    -> std::function<bool(const nlohmann::json &)> {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    return [msgId](const nlohmann::json &frame) -> bool {
        return frame.value("type", "") == linko::kTypeMsgStored &&
               frame.contains("body") && frame["body"].value("id", "") == msgId;
    };
}

// Frame matcher: session.error with `code`.
auto errorOf(std::string_view code)
    -> std::function<bool(const nlohmann::json &)> {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    return [code](const nlohmann::json &frame) -> bool {
        return frame.value("type", "") == linko::kTypeSessionError &&
               frame.contains("body") &&
               frame["body"].value("code", "") == code;
    };
}

// Reads frames until one matches, skipping everything else (presence, the
// other side's acks); returns the raw wire bytes of the match (empty when
// nothing matched within the budget).
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

// Bounds a drain: sends a session.ping and collects every frame until the
// pong (inclusive). Whatever the server pushed between the last action and
// the probe is inside the returned window.
auto drainUntilPong(WsClient &client) -> std::vector<std::string> {
    client.sendText(linko::serialize(
        wireEnvelope(linko::kTypeSessionPing, nlohmann::json::object())));
    std::vector<std::string> frames;
    for (;;) {
        auto wire = client.receive();
        const auto parsed = parseJson(wire);
        frames.push_back(wire);
        if (!parsed.is_discarded() &&
            parsed.value("type", "") == std::string(linko::kTypeSessionPong)) {
            return frames;
        }
    }
}

// Counts msg.deliver frames for `msgId` inside a drained window.
auto countDelivers(const std::vector<std::string> &frames,
                   const std::string &msgId) -> int {
    int count = 0;
    for (const auto &wire : frames) {
        const auto parsed = parseJson(wire);
        if (!parsed.is_discarded() && deliverOf(msgId)(parsed)) {
            ++count;
        }
    }
    return count;
}

// The seq numbers of the msg.deliver frames inside a drained window, in
// arrival order.
auto deliverSeqs(const std::vector<std::string> &frames)
    -> std::vector<std::int64_t> {
    std::vector<std::int64_t> seqs;
    for (const auto &wire : frames) {
        const auto parsed = parseJson(wire);
        if (!parsed.is_discarded() &&
            parsed.value("type", "") == std::string(linko::kTypeMsgDeliver)) {
            seqs.push_back(
                parsed["body"]["message"].value("seq", std::int64_t{0}));
        }
    }
    return seqs;
}

auto msgSendBody(const std::string &msgId, const std::string &recipient,
                 const std::string &text) -> nlohmann::json {
    return linko::MsgSend{msgId, recipient, text, std::nullopt}.toBody();
}

// Stores `record`; fails the test and returns a default record when the
// store rejects it (an explicit has_value() check, which the optional
// access analyzer can see).
auto expectStored(server::Store &store, const linko::MessageRecord &record,
                  const std::string &what) -> linko::MessageRecord {
    const auto stored = store.storeMessage(record);
    if (!stored.has_value()) {
        ADD_FAILURE() << what;
        return {};
    }
    return *stored;
}

// Fails the test when the optional is empty; returns a default record
// otherwise.
auto expectPresent(const std::optional<linko::MessageRecord> &record,
                   const std::string &what) -> linko::MessageRecord {
    if (!record.has_value()) {
        ADD_FAILURE() << what;
        return {};
    }
    return *record;
}

// Sends one message from `sender` and waits for the msg.stored ack on the
// sender's socket and, when `receiver` is set, the msg.deliver on the
// receiver's socket. Fails the test on a missing frame; returns the
// msg.stored body (the server-assigned seq/ts) for further assertions.
auto sendAndExpect(WsClient &sender, WsClient *receiver,
                   const std::string &msgId, const std::string &recipient,
                   const std::string &text) -> nlohmann::json {
    sender.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgSend, msgSendBody(msgId, recipient, text))));
    const auto stored = parseJson(waitFor(sender, storedOf(msgId)));
    if (stored.is_discarded()) {
        ADD_FAILURE() << "no msg.stored for " << msgId;
        return nlohmann::json::object();
    }
    if (receiver != nullptr && waitFor(*receiver, deliverOf(msgId)).empty()) {
        ADD_FAILURE() << "no msg.deliver for " << msgId;
    }
    return stored["body"];
}

} // namespace

// --- Store v2: message tables and receipts ---

TEST(Messaging, ConversationKeyIsLexicographic) {
    EXPECT_EQ(server::conversationKey("bob", "alice"), std::string("alice\x1f"
                                                                   "bob"));
    EXPECT_EQ(server::conversationKey("alice", "bob"),
              server::conversationKey("bob", "alice"));
}

TEST(MessagingStore, StoreMessageAssignsSeqAndServerTs) {
    const auto store = storeTest("seq");

    const auto stored = expectStored(*store,
                                     linko::MessageRecord{
                                         "m1",
                                         "alice",
                                         "bob",
                                         "hi",
                                         std::nullopt,
                                         0,
                                         0,
                                     },
                                     "the store must accept the message");
    EXPECT_EQ(stored.seq, 1);
    EXPECT_EQ(stored.ts, kBaseMs);
    EXPECT_EQ(stored.from, "alice");
    EXPECT_EQ(stored.to, "bob");
    EXPECT_EQ(stored.text, "hi");

    const auto storedSecond =
        expectStored(*store,
                     linko::MessageRecord{
                         "m2",
                         "alice",
                         "bob",
                         "again",
                         std::nullopt,
                         0,
                         0,
                     },
                     "the store must accept the second message");
    EXPECT_EQ(storedSecond.seq, 2);

    // A different conversation counts from its own 1.
    const auto storedOther =
        expectStored(*store,
                     linko::MessageRecord{
                         "m3",
                         "carol",
                         "dave",
                         "hey",
                         std::nullopt,
                         0,
                         0,
                     },
                     "the store must accept the other message");
    EXPECT_EQ(storedOther.seq, 1);
}

TEST(MessagingStore, StoreMessageDuplicateIdReturnsNullopt) {
    const auto store = storeTest("dup");

    static_cast<void>(expectStored(*store,
                                   linko::MessageRecord{
                                       "m1",
                                       "alice",
                                       "bob",
                                       "hi",
                                       std::nullopt,
                                       0,
                                       0,
                                   },
                                   "the store must accept the message"));

    // The same id with different content stores nothing (idempotent sends):
    // nullopt, and the original row is intact for the replay.
    const linko::MessageRecord replay{
        "m1", "alice", "bob", "changed text", std::nullopt, 0, 0,
    };
    EXPECT_FALSE(store->storeMessage(replay).has_value());

    const auto original =
        expectPresent(store->messageById("m1"),
                      "the original row must survive the duplicate send");
    EXPECT_EQ(original.text, "hi");
    EXPECT_EQ(original.seq, 1);
    EXPECT_EQ(original.ts, kBaseMs);
    EXPECT_FALSE(store->messageById("missing").has_value());

    const auto all =
        store->messagesAfter(server::conversationKey("alice", "bob"), 0);
    ASSERT_EQ(all.size(), 1U);
    EXPECT_EQ(all.front().text, "hi");
}

TEST(MessagingStore, MessagesAfterOrdersBySeqAcrossDirections) {
    const auto store = storeTest("after");
    const auto conv = server::conversationKey("alice", "bob");

    static_cast<void>(store->storeMessage({
        "m1",
        "alice",
        "bob",
        "one",
        std::nullopt,
        0,
        0,
    }));
    static_cast<void>(store->storeMessage({
        "m2",
        "bob",
        "alice",
        "two",
        std::nullopt,
        0,
        0,
    }));
    static_cast<void>(store->storeMessage({
        "m3",
        "alice",
        "bob",
        "three",
        std::nullopt,
        0,
        0,
    }));
    // An unrelated conversation stays out.
    static_cast<void>(store->storeMessage({
        "m4",
        "carol",
        "dave",
        "elsewhere",
        std::nullopt,
        0,
        0,
    }));

    const auto all = store->messagesAfter(conv, 0);
    ASSERT_EQ(all.size(), 3U);
    EXPECT_EQ(all[0].seq, 1);
    EXPECT_EQ(all[0].text, "one");
    EXPECT_EQ(all[1].seq, 2);
    EXPECT_EQ(all[1].from, "bob");
    EXPECT_EQ(all[2].seq, 3);

    const auto afterFirst = store->messagesAfter(conv, 1);
    ASSERT_EQ(afterFirst.size(), 2U);
    EXPECT_EQ(afterFirst[0].seq, 2);
}

TEST(MessagingStore, MessageFileMetaRoundtrips) {
    const auto store = storeTest("file");

    const linko::FileMeta meta{"report.pdf", 1024, "abc", "server", "file-1"};
    linko::MessageRecord withFile{
        "m1", "alice", "bob", "see attached", meta, 0, 0,
    };
    const auto stored = store->storeMessage(withFile);
    if (!stored.has_value()) {
        FAIL() << "the store must accept the message";
    }
    if (!stored->file.has_value()) {
        FAIL() << "the file metadata must roundtrip";
    }
    EXPECT_EQ(*stored->file, meta);

    const auto all =
        store->messagesAfter(server::conversationKey("alice", "bob"), 0);
    ASSERT_EQ(all.size(), 1U);
    if (!all.front().file.has_value()) {
        FAIL() << "the file metadata must roundtrip";
    }
    EXPECT_EQ(*all.front().file, meta);
}

TEST(MessagingStore, ReceiptsAdvanceMonotonically) {
    const auto store = storeTest("receipts");
    const auto conv = server::conversationKey("alice", "bob");

    auto receipts = store->receiptsOf(conv, "bob", "alice");
    EXPECT_EQ(receipts.first, 0);
    EXPECT_EQ(receipts.second, 0);

    store->advanceReceipts(conv, "bob", "alice", kDeliveredUpto, 0);
    receipts = store->receiptsOf(conv, "bob", "alice");
    EXPECT_EQ(receipts.first, kDeliveredUpto);
    EXPECT_EQ(receipts.second, 0);

    // Lower values are ignored; only the read watermark moves here.
    store->advanceReceipts(conv, "bob", "alice", kStaleDelivered, kReadUpto);
    receipts = store->receiptsOf(conv, "bob", "alice");
    EXPECT_EQ(receipts.first, kDeliveredUpto);
    EXPECT_EQ(receipts.second, kReadUpto);

    store->advanceReceipts(conv, "bob", "alice", kStaleDelivered,
                           kStaleDelivered);
    receipts = store->receiptsOf(conv, "bob", "alice");
    EXPECT_EQ(receipts.first, kDeliveredUpto);
    EXPECT_EQ(receipts.second, kReadUpto);

    // The other holder's row is independent.
    const auto aliceReceipts = store->receiptsOf(conv, "alice", "bob");
    EXPECT_EQ(aliceReceipts.first, 0);
    EXPECT_EQ(aliceReceipts.second, 0);
}

// --- Integration: the wire behavior over the full stack ---

TEST(Messaging, SendStoredAndDeliveredOnline) {
    MessagingFixture fixture("send-online");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeMsgSend, msgSendBody("m1", "bob", "hi"))));

    const auto storedWire = waitFor(alice, storedOf("m1"));
    ASSERT_FALSE(storedWire.empty());
    const auto stored = parseJson(storedWire);
    EXPECT_EQ(stored["body"].value("seq", 0), 1);
    // An int64 default: the epoch milliseconds exceed 32 bits.
    EXPECT_EQ(stored["body"].value("ts", std::int64_t{0}), kBaseMs);

    const auto deliverWire = waitFor(bob, deliverOf("m1"));
    ASSERT_FALSE(deliverWire.empty());
    const auto deliver = parseJson(deliverWire);
    const auto &message = deliver["body"]["message"];
    EXPECT_EQ(message.value("id", ""), "m1");
    EXPECT_EQ(message.value("from", ""), "alice");
    EXPECT_EQ(message.value("to", ""), "bob");
    EXPECT_EQ(message.value("text", ""), "hi");
    EXPECT_EQ(message.value("seq", 0), 1);
}

TEST(Messaging, DuplicateSendReturnsOriginalSeq) {
    MessagingFixture fixture("duplicate");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    sendAndExpect(alice, &bob, "m1", "bob", "hi");

    // The replay gets the original seq back and stores nothing new.
    alice.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgSend, msgSendBody("m1", "bob", "changed text"))));
    const auto replayWire = waitFor(alice, storedOf("m1"));
    ASSERT_FALSE(replayWire.empty());
    EXPECT_EQ(parseJson(replayWire)["body"].value("seq", 0), 1);

    // Exactly one message row exists, and the online peer saw no second
    // deliver: the sync replay returns the single row and the drain bounds
    // the window.
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgSync, linko::MsgSync{"alice", 0}.toBody())));
    const auto drained = drainUntilPong(bob);
    EXPECT_EQ(countDelivers(drained, "m1"), 1);
}

TEST(Messaging, SeqMonotonicAcrossDirections) {
    MessagingFixture fixture("seq-shared");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    const auto first = sendAndExpect(alice, nullptr, "m1", "bob", "one");
    ASSERT_EQ(first.value("seq", 0), 1);

    const auto second = sendAndExpect(bob, nullptr, "m2", "alice", "two");
    ASSERT_EQ(second.value("seq", 0), 2);

    const auto third = sendAndExpect(alice, nullptr, "m3", "bob", "three");
    ASSERT_EQ(third.value("seq", 0), 3);
}

TEST(Messaging, OfflineDeliveredInSeqOrderOnConnect) {
    MessagingFixture fixture("offline");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());

    // Bob is registered but offline: all three messages queue up.
    sendAndExpect(alice, nullptr, "m1", "bob", "one");
    sendAndExpect(alice, nullptr, "m2", "bob", "two");
    sendAndExpect(alice, nullptr, "m3", "bob", "three");

    WsClient bob("token-bob", fixture.port());
    // The connect hook pushes the backlog; the probe bounds the drain.
    const auto seqs = deliverSeqs(drainUntilPong(bob));
    ASSERT_EQ(seqs.size(), 3U);
    EXPECT_EQ(seqs, (std::vector<std::int64_t>{1, 2, 3}));
}

TEST(Messaging, AckForwardedAndWatermarksAdvance) {
    MessagingFixture fixture("ack");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    sendAndExpect(alice, &bob, "m1", "bob", "one");
    sendAndExpect(alice, &bob, "m2", "bob", "two");

    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgAckDelivered, linko::MsgAck{"alice", 2}.toBody())));
    const auto ackWire = waitFor(alice, typeIs(linko::kTypeMsgAckDelivered));
    ASSERT_FALSE(ackWire.empty());
    // The envelope is forwarded unchanged: same body the client sent.
    const auto ack = parseJson(ackWire);
    EXPECT_EQ(ack["body"].value("conversation", ""), "alice");
    EXPECT_EQ(ack["body"].value("uptoSeq", 0), 2);

    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgAckRead, linko::MsgAck{"alice", 2}.toBody())));
    ASSERT_FALSE(waitFor(alice, typeIs(linko::kTypeMsgAckRead)).empty());

    // Holder bob's watermarks for the alice conversation moved.
    const auto receipts = fixture.store().receiptsOf(
        server::conversationKey("alice", "bob"), "bob", "alice");
    EXPECT_EQ(receipts.first, 2);
    EXPECT_EQ(receipts.second, 2);
}

TEST(Messaging, ReceiptsNeverRegress) {
    MessagingFixture fixture("receipts");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());
    WsClient bob("token-bob", fixture.port());

    sendAndExpect(alice, &bob, "m1", "bob", "one");

    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgAckDelivered, linko::MsgAck{"alice", 1}.toBody())));
    ASSERT_FALSE(waitFor(alice, typeIs(linko::kTypeMsgAckDelivered)).empty());

    // A stale ack (lower uptoSeq) is forwarded but moves nothing backwards.
    bob.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgAckDelivered, linko::MsgAck{"alice", 1}.toBody())));
    ASSERT_FALSE(waitFor(alice, typeIs(linko::kTypeMsgAckDelivered)).empty());

    const auto receipts = fixture.store().receiptsOf(
        server::conversationKey("alice", "bob"), "bob", "alice");
    EXPECT_EQ(receipts.first, 1);
}

TEST(Messaging, SyncAfterSeq) {
    MessagingFixture fixture("sync");
    registerToken(fixture.store(), "alice", "token-alice");
    registerToken(fixture.store(), "bob", "token-bob");
    WsClient alice("token-alice", fixture.port());

    sendAndExpect(alice, nullptr, "m1", "bob", "one");
    sendAndExpect(alice, nullptr, "m2", "bob", "two");
    sendAndExpect(alice, nullptr, "m3", "bob", "three");

    alice.sendText(linko::serialize(
        wireEnvelope(linko::kTypeMsgSync, linko::MsgSync{"bob", 1}.toBody())));
    // Everything after seq 1, in seq order; seq 1 itself is not resent.
    const auto seqs = deliverSeqs(drainUntilPong(alice));
    ASSERT_EQ(seqs.size(), 2U);
    EXPECT_EQ(seqs, (std::vector<std::int64_t>{2, 3}));
}

TEST(Messaging, SendToUnknownUserRejected) {
    MessagingFixture fixture("unknown-user");
    registerToken(fixture.store(), "alice", "token-alice");
    WsClient alice("token-alice", fixture.port());

    alice.sendText(linko::serialize(wireEnvelope(
        linko::kTypeMsgSend, msgSendBody("m1", "ghost", "into the void"))));

    ASSERT_FALSE(waitFor(alice, errorOf("user_not_found")).empty());

    // Nothing was stored for the never-opened conversation.
    const auto stored = fixture.store().messagesAfter(
        server::conversationKey("alice", "ghost"), 0);
    EXPECT_TRUE(stored.empty());
}
