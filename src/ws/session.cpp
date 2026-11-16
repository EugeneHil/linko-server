// WebSocket session implementation (Plan 3 Task 5).
#include "server/ws_session.hpp"

#include <boost/beast/websocket/ssl.hpp>

#include <utility>
#include <vector>

#include "linko/messages.hpp"
#include "server/wire.hpp"

namespace server {

namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>

namespace {

// How often the idle deadline is checked in wall time; the deadline itself
// is computed on the injected clock, so tests advance time without sleeps.
constexpr std::int64_t kIdleCheckQuantumMs = 100;
constexpr std::int64_t kMsPerSecond = 1000;
constexpr std::int64_t kRateWindowMs = 60 * kMsPerSecond;

auto errorEnvelope(const std::string &code, const std::string &detail,
                   std::int64_t nowMs) -> std::string {
    const auto envelope =
        makeEnvelope(linko::kTypeSessionError,
                     linko::SessionError{code, detail}.toBody(), nowMs);
    return toWire(envelope);
}

} // namespace

WsSession::WsSession(Stream stream,
                     const http::request<http::string_body> &upgradeRequest,
                     Device device, const Limits &limits, Clock nowMs, Hub &hub,
                     // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                     ProtocolSink &callSink, ProtocolSink &msgSink)
    : stream_(std::move(stream)), upgradeRequest_(upgradeRequest),
      device_(std::move(device)), limits_(limits), nowMs_(std::move(nowMs)),
      hub_(hub), callSink_(callSink), msgSink_(msgSink),
      idleTimer_(stream_.get_executor()), lastActivityMs_(nowMs_()) {}

WsSession::~WsSession() noexcept { // NOLINT(bugprone-exception-escape)
    static_cast<void>(idleTimer_.cancel());
}

void WsSession::run() {
    // Protocol v1 is text-only and bounded by the envelope size cap; a
    // bigger frame fails the read with message_too_big (close 1009).
    stream_.read_message_max(linko::kMaxEnvelopeBytes);
    // The upgrade request bytes were consumed by the HTTP session, so the
    // accept is given the request explicitly (the no-argument form would
    // wait for another request and never complete).
    stream_.async_accept(
        upgradeRequest_,
        beast::bind_front_handler(&WsSession::onAccept, shared_from_this()));
}

void WsSession::onAccept(beast::error_code errorCode) {
    if (errorCode) {
        drop();
        return;
    }
    // The hub registration (and its presence broadcast) must happen only
    // after the upgrade response is out: frames before the handshake would
    // corrupt the server-side WebSocket state.
    hub_.attach(device_, this);
    armIdleTimer();
    doRead();
}

void WsSession::doRead() {
    stream_.async_read(
        readBuffer_,
        beast::bind_front_handler(&WsSession::onRead, shared_from_this()));
}

void WsSession::onRead(beast::error_code errorCode,
                       std::size_t /*bytesTransferred*/) {
    if (errorCode) {
        if (errorCode == websocket::error::message_too_big) {
            close(kWsCloseTooBig);
            return;
        }
        drop();
        return;
    }
    if (stream_.got_binary()) {
        close(kWsCloseUnsupportedData);
        return;
    }
    lastActivityMs_ = nowMs_();
    const auto wire = beast::buffers_to_string(readBuffer_.data());
    readBuffer_.consume(readBuffer_.size());
    handleWire(wire);
    if (!closing_ && !dropping_) {
        doRead();
    }
}

void WsSession::handleWire(std::string_view wire) {
    // Per-connection envelope budget (spec 4.5: per-connection message rate
    // limit): every received envelope counts; an over-budget one is told
    // and closed 4002.
    const std::int64_t now = nowMs_();
    while (!rateWindow_.empty() && rateWindow_.front() <= now - kRateWindowMs) {
        rateWindow_.pop_front();
    }
    if (static_cast<std::int64_t>(rateWindow_.size()) >=
        limits_.envelopesPerMinute) {
        static_cast<void>(send(errorEnvelope("rate_limited", "", now)));
        close(kWsCloseRateLimited);
        return;
    }
    rateWindow_.push_back(now);

    const auto result = linko::parseEnvelope(wire);
    if (result.unsupportedVersion) {
        static_cast<void>(send(errorEnvelope("unsupported_version", "", now)));
        close(kWsCloseNormal);
        return;
    }
    if (!result.errors.empty()) {
        const auto &first = result.errors.front();
        static_cast<void>(send(errorEnvelope(
            "invalid_envelope", first.path + ": " + first.message, now)));
        return;
    }
    if (!result.envelope.has_value()) {
        return;
    }
    const auto &envelope = *result.envelope;
    if (envelope.type == linko::kTypeSessionPing) {
        static_cast<void>(send(toWire(makeEnvelope(
            linko::kTypeSessionPong, nlohmann::json::object(), now))));
        return;
    }
    if (envelope.type == linko::kTypeSessionHello) {
        std::vector<linko::ValidationError> helloErrors;
        const auto hello =
            linko::SessionHello::fromBody(envelope.body, helloErrors);
        if (!hello.has_value() || hello->user != device_.user) {
            static_cast<void>(send(errorEnvelope("hello_mismatch", "", now)));
            close(kWsCloseHelloMismatch);
        }
        return;
    }
    if (envelope.type == linko::kTypePresenceChanged) {
        return; // presence is server-owned
    }
    if (envelope.type.rfind("call.", 0) == 0 ||
        envelope.type.rfind("file.", 0) == 0) {
        callSink_.onEnvelope(device_.user, envelope, device_.id);
        return;
    }
    if (envelope.type.rfind("msg.", 0) == 0) {
        msgSink_.onEnvelope(device_.user, envelope, device_.id);
    }
}

auto WsSession::send(std::string_view wire) -> bool {
    {
        const std::scoped_lock lock(writeMutex_);
        if (closing_ || dropping_) {
            return false;
        }
        outgoing_.emplace_back(wire);
        if (writing_) {
            return true;
        }
        writing_ = true;
    }
    doWrite();
    return true;
}

void WsSession::doWrite() {
    {
        const std::scoped_lock lock(writeMutex_);
        if (outgoing_.empty()) {
            writing_ = false;
            return;
        }
        // pending_ owns the bytes until the write completes.
        pending_ = std::move(outgoing_.front());
        outgoing_.pop_front();
    }
    auto self = shared_from_this();
    stream_.text(true);
    stream_.async_write(
        asio::buffer(pending_),
        [self, this](beast::error_code errorCode, std::size_t) -> void {
            if (errorCode) {
                drop();
                return;
            }
            bool startClose = false;
            {
                const std::scoped_lock lock(writeMutex_);
                if (outgoing_.empty()) {
                    writing_ = false;
                    // Close only after the write queue drained: beast
                    // forbids an async_close while a write is outstanding
                    // (it would drop the close frame).
                    startClose = closing_;
                }
            }
            if (startClose) {
                doClose();
                return;
            }
            doWrite();
        });
}

void WsSession::close(unsigned short code) {
    bool startClose = false;
    {
        const std::scoped_lock lock(writeMutex_);
        if (closing_) {
            return;
        }
        closing_ = true;
        pendingCloseCode_ = code;
        startClose = !writing_;
    }
    if (startClose) {
        doClose();
    }
}

void WsSession::doClose() {
    auto self = shared_from_this();
    stream_.async_close(websocket::close_reason(pendingCloseCode_),
                        [self](beast::error_code) -> void {});
}

void WsSession::armIdleTimer() {
    idleTimer_.expires_after(std::chrono::milliseconds(kIdleCheckQuantumMs));
    auto self = shared_from_this();
    idleTimer_.async_wait(
        [self](beast::error_code) -> void { self->checkIdle(); });
}

void WsSession::checkIdle() {
    if (dropping_ || closing_) {
        return;
    }
    const std::int64_t idleDeadline =
        lastActivityMs_ +
        (static_cast<std::int64_t>(limits_.idleTimeoutSec) * kMsPerSecond);
    if (nowMs_() >= idleDeadline) {
        static_cast<void>(send(errorEnvelope("idle_timeout", "", nowMs_())));
        close(kWsCloseNormal);
        return;
    }
    armIdleTimer();
}

void WsSession::drop() {
    if (dropping_) {
        return;
    }
    dropping_ = true;
    idleTimer_.cancel();
    hub_.detach(device_, this);
    callSink_.onSocketDrop(device_.user);
    msgSink_.onSocketDrop(device_.user);
}

} // namespace server
