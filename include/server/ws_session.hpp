// WebSocket session (design spec 4.5): one authenticated device connection.
// The session validates the token at upgrade time (the listener does that),
// then guards frames (size, rate, idle), answers session.ping, routes
// envelope families to the protocol sinks and broadcasts presence through
// the hub. The injected clock drives rate and idle decisions, so tests move
// time forward explicitly.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <deque>

#include "linko/envelope.hpp"
#include "server/config.hpp"
#include "server/hub.hpp"
#include "server/store.hpp"

namespace server {

// WebSocket close codes this server uses (RFC 6455 plus the 4000-4999
// application range).
inline constexpr unsigned short kWsCloseUnsupportedData = 1003;
inline constexpr unsigned short kWsCloseNormal = 1000;
inline constexpr unsigned short kWsCloseTooBig = 1009;
inline constexpr unsigned short kWsCloseAnotherSocket = 4001;
inline constexpr unsigned short kWsCloseRateLimited = 4002;
inline constexpr unsigned short kWsCloseHelloMismatch = 4003;

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>

// Where the session delivers envelopes it does not handle itself: call.*
// and file.* go to the call registry sink, msg.* to the messaging sink.
// Both default to the drop-all sink until their tasks land (Plan 3
// Tasks 6-7).
class ProtocolSink {
  public:
    ProtocolSink() = default;
    virtual ~ProtocolSink() = default;
    ProtocolSink(const ProtocolSink &) = delete;
    auto operator=(const ProtocolSink &) -> ProtocolSink & = delete;

    virtual void onEnvelope(const std::string &fromUser,
                            const linko::Envelope &envelope,
                            std::int64_t deviceId) = 0;
    virtual void onSocketDrop(const std::string &user) = 0;
};

// The default sink: swallows everything (Plan 3 Tasks 6-7 replace it).
class NullSink final : public ProtocolSink {
  public:
    void onEnvelope(const std::string & /*fromUser*/,
                    const linko::Envelope & /*envelope*/,
                    std::int64_t /*deviceId*/) override {}
    void onSocketDrop(const std::string & /*user*/) override {}
};

class WsSession : public std::enable_shared_from_this<WsSession> {
  public:
    using Clock = std::function<std::int64_t()>; // epoch milliseconds
    using Stream =
        beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>>;

    // Takes over an accepted TLS connection whose HTTP upgrade request was
    // already authenticated and read by the listener; the request is kept
    // because the beast accept needs it (the bytes are already consumed).
    WsSession(
        Stream stream,
        const beast::http::request<beast::http::string_body> &upgradeRequest,
        Device device, const Limits &limits, Clock nowMs, Hub &hub,
        ProtocolSink &callSink, ProtocolSink &msgSink);
    ~WsSession() noexcept;

    WsSession(const WsSession &) = delete;
    auto operator=(const WsSession &) -> WsSession & = delete;

    // Attaches to the hub (closing any previous socket of the same device,
    // broadcasting presence) and runs the read loop until the connection
    // drops or the session closes it.
    void run();

    // Queues one text frame to the device. Returns false when the session
    // is no longer open; safe to call from any thread.
    auto send(std::string_view wire) -> bool;

    // Begins the close handshake with the given code (4001 another socket,
    // 1000 idle, 4002 rate, 4003 hello mismatch, ...).
    void close(unsigned short code);

  private:
    void onAccept(beast::error_code errorCode);
    void doRead();
    void onRead(beast::error_code errorCode, std::size_t bytesTransferred);
    void handleWire(std::string_view wire);
    void doWrite();
    void doClose();
    void onWrite(beast::error_code errorCode, std::size_t /*bytes*/);
    void armIdleTimer();
    void checkIdle();
    void drop();

    Stream stream_;
    beast::http::request<beast::http::string_body> upgradeRequest_;
    beast::flat_buffer readBuffer_;
    std::string pending_;
    std::deque<std::string> outgoing_;
    bool writing_ = false;
    bool closing_ = false;
    unsigned short pendingCloseCode_ = kWsCloseNormal;
    bool dropping_ = false;
    Device device_;
    Limits limits_;
    Clock nowMs_;
    Hub &hub_;
    ProtocolSink &callSink_;
    ProtocolSink &msgSink_;
    std::mutex writeMutex_;
    asio::steady_timer idleTimer_;
    std::deque<std::int64_t> rateWindow_;
    std::int64_t lastActivityMs_ = 0;
};

} // namespace server
