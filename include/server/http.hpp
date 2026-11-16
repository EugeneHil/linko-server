// HTTP layer (design spec 4.5): a TLS-only Beast listener with an exact-path
// router, plus the invite-registration endpoint. Every request is logged as
// "addr method path status duration_ms" (query stripped); the handler
// interface stays transport-agnostic so tests drive handlers directly.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "server/config.hpp"
#include "server/hub.hpp"
#include "server/store.hpp"
#include "server/throttle.hpp"
#include "server/ws_session.hpp"

namespace server {

struct HttpRequest {
    std::string method;
    std::string target; // path with query string, as received
    std::string body;
    std::string authorization; // raw Authorization header value
    std::string address;       // client address, e.g. "127.0.0.1"
};

inline constexpr int kDefaultHttpStatus = 200;

struct HttpResponse {
    int status = kDefaultHttpStatus;
    std::string body;

    auto operator==(const HttpResponse &other) const -> bool {
        return status == other.status && body == other.body;
    }
};

using HttpHandler = std::function<HttpResponse(const HttpRequest &)>;

// Routes by exact (method, path); the query string is stripped before
// matching. Unknown path -> 404, known path with wrong method -> 405.
class Router {
  public:
    void add(const std::string &method, const std::string &path,
             HttpHandler handler);
    [[nodiscard]] auto dispatch(const HttpRequest &request) const
        -> HttpResponse;

  private:
    // Keyed by "METHOD path" for exact lookup plus the set of known paths
    // for the 405 answer.
    std::vector<std::pair<std::string, HttpHandler>> routes_;
    std::vector<std::string> knownPaths_;
};

// Bearer <device token> -> the live device behind it, nullopt otherwise;
// shared by every authenticated endpoint (defined in users_handler.cpp).
[[nodiscard]] auto authenticateBearer(Store &store, const HttpRequest &request)
    -> std::optional<Device>;

// GET /api/v1/users?prefix= (Bearer): username prefix search, max 20.
[[nodiscard]] auto handleUsers(Store &store, const HttpRequest &request)
    -> HttpResponse;

// GET /api/v1/turn (Bearer): short-lived TURN REST credentials (spec 4.6).
[[nodiscard]] auto handleTurn(const Config &config, Store &store,
                              const HttpRequest &request) -> HttpResponse;

// POST /api/v1/register: consumes the invite code for `username`, creates
// the user/device, returns the device token (shown exactly once). 400 on
// malformed JSON or a bad username, 403 on an unusable invite, 429 when the
// address exceeded its per-minute attempt budget.
[[nodiscard]] auto handleRegister(Store &store, Throttle &throttle,
                                  const HttpRequest &request) -> HttpResponse;

// TLS-only HTTPS listener: one Beast session per connection, each on its
// own strand; request bodies are capped at 64 KiB; every completed request
// goes through logRequest. Connections are closed after one response
// (HTTP/1.1 keep-alive arrives with the WebSocket task, where sessions are
// long-lived anyway).
// Wiring for the GET /ws upgrade path: token authentication and the sinks
// the accepted WebSocket session feeds. Null when the deployment runs
// without WebSocket support (tests of the HTTP-only surface).
struct WsHooks {
    std::function<std::optional<Device>(const std::string &authorization)>
        authenticate;
    Hub *hub = nullptr;
    ProtocolSink *callSink = nullptr;
    ProtocolSink *msgSink = nullptr;
    Limits limits;
    std::function<std::int64_t()> nowMs;
};

class Listener {
  public:
    Listener(boost::asio::io_context &ioContext,
             boost::asio::ssl::context &sslContext, Router &router,
             const WsHooks *wsHooks = nullptr);

    // Binds to `bindAddress:port` (port 0 = ephemeral) and starts the
    // accept loop. Throws std::runtime_error on bind failures.
    void listen(const std::string &bindAddress, unsigned short port);

    // The actually bound port (resolve after listen(); ephemeral port 0
    // becomes concrete). Makes integration tests deterministic.
    [[nodiscard]] auto port() const -> unsigned short;

  private:
    void doAccept();

    class Session;

    boost::asio::io_context &ioContext_;
    const WsHooks *wsHooks_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    boost::asio::ssl::context &sslContext_;
    Router &router_;
};

} // namespace server
