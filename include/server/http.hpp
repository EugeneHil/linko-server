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
#include "server/file_store.hpp"
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
    // The declared body size (Content-Length), nullopt when the request
    // carried none (absent, malformed or chunked) - the upload length
    // check's input (Plan 3 Task 8).
    std::optional<std::int64_t> contentLength;
};

inline constexpr int kDefaultHttpStatus = 200;

struct HttpResponse {
    int status = kDefaultHttpStatus;
    std::string body;

    // File downloads (Plan 3 Task 8): when set, the listener streams this
    // file's bytes as the response body instead of `body`, carrying
    // fileSha256 in the X-Linko-Sha256 header.
    std::string fileForStreaming;
    std::string fileSha256;

    // The (status, body) form every handler builds from; file downloads
    // fill the streaming fields afterwards. Declared so the ubiquitous
    // two-field brace init stays valid now that the struct has four fields.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    HttpResponse(int statusCode, std::string bodyText)
        : status(statusCode), body(std::move(bodyText)) {}
    HttpResponse() = default;

    auto operator==(const HttpResponse &other) const -> bool {
        return status == other.status && body == other.body &&
               fileForStreaming == other.fileForStreaming &&
               fileSha256 == other.fileSha256;
    }
};

using HttpHandler = std::function<HttpResponse(const HttpRequest &)>;

// Routes by exact (method, path); the query string is stripped before
// matching. Unknown path -> 404, known path with wrong method -> 405. A
// prefix route (addPrefix) matches any path that starts with its prefix,
// after the exact routes.
class Router {
  public:
    void add(const std::string &method, const std::string &path,
             HttpHandler handler);

    // Dispatches any (method, path) whose path starts with `prefix` (Plan 3
    // Task 8: GET /api/v1/files/{id}); checked after the exact routes.
    void addPrefix(const std::string &method, const std::string &prefix,
                   HttpHandler handler);

    [[nodiscard]] auto dispatch(const HttpRequest &request) const
        -> HttpResponse;

  private:
    // One prefix route, matched by method and path prefix.
    struct PrefixRoute {
        std::string method;
        std::string prefix;
        HttpHandler handler;
    };

    // Keyed by "METHOD path" for exact lookup plus the set of known paths
    // for the 405 answer.
    std::vector<std::pair<std::string, HttpHandler>> routes_;
    std::vector<std::string> knownPaths_;
    std::vector<PrefixRoute> prefixRoutes_;
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

// GET /api/v1/files/{id} (Bearer): streams the stored file's bytes with the
// digest in the X-Linko-Sha256 header; 404 for an unknown or malformed id.
[[nodiscard]] auto handleFileDownload(Store &store, FileStore &files,
                                      const HttpRequest &request)
    -> HttpResponse;

// The header phase of PUT /api/v1/files (Plan 3 Task 8): the error response
// when the request must not stream - 411 without Content-Length, 413 over
// Limits::maxFileBytes, 507 over Limits::userQuotaBytes for `owner` -
// nullopt when the body may stream into the FileStore. The bearer check
// itself runs in the listener (it owns the connection).
[[nodiscard]] auto checkUploadHeaders(Store &store, const Limits &limits,
                                      const std::string &owner,
                                      const HttpRequest &request)
    -> std::optional<HttpResponse>;

// The completion phase of PUT /api/v1/files: records the file row and
// builds the 201 {"fileId","sha256","size"} response the client mirrors
// into the message's FileMeta{transport:"server"}.
[[nodiscard]] auto finishUpload(Store &store, const std::string &owner,
                                FileStore &files, const std::string &fileId,
                                std::int64_t size, const std::string &sha256Hex,
                                std::int64_t nowMs) -> HttpResponse;

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

// Streaming file uploads (Plan 3 Task 8): PUT /api/v1/files streams its
// body to disk through these hooks. The listener intercepts the route
// before the router because the body arrives chunk-by-chunk and must not be
// buffered whole; null when the deployment has no file storage.
struct UploadHooks {
    Store *store = nullptr;
    FileStore *files = nullptr;
    Limits limits;
    std::function<std::int64_t()> nowMs;
};

class Listener {
  public:
    Listener(boost::asio::io_context &ioContext,
             boost::asio::ssl::context &sslContext, Router &router,
             const WsHooks *wsHooks = nullptr,
             const UploadHooks *uploadHooks = nullptr);

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
    const UploadHooks *uploadHooks_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    boost::asio::ssl::context &sslContext_;
    Router &router_;
};

} // namespace server
