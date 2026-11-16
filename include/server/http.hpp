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

#include "server/store.hpp"
#include "server/throttle.hpp"

namespace server {

struct HttpRequest {
    std::string method;
    std::string target; // path with query string, as received
    std::string body;
    std::string authorization; // raw Authorization header value
    std::string address;       // client address, e.g. "127.0.0.1"
};

struct HttpResponse {
    int status = 200;
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
class Listener {
  public:
    Listener(boost::asio::io_context &ioContext,
             boost::asio::ssl::context &sslContext, Router &router);

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
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    boost::asio::ssl::context &sslContext_;
    Router &router_;
};

} // namespace server
