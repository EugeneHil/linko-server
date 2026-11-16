// Listener implementation (Plan 3 Task 4/5/8): TLS-only Beast accept loop,
// one session per connection on its own strand, one HTTP request per
// connection, and the GET /ws upgrade path into WebSocket sessions. Every
// completed HTTP request is logged. Bodies are read chunk-by-chunk through
// a buffer_body parser: normal requests accumulate into memory (bounded by
// the 64 KiB frame limit), PUT /api/v1/files streams into the FileStore
// with an on-the-fly digest (no whole-file buffering).
#include "server/http.hpp"

#include <chrono>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "server/crypto.hpp"
#include "server/log.hpp"
#include "server/ws_session.hpp"

namespace server {

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>
namespace ssl = asio::ssl;      // from <boost/asio/ssl.hpp>
using asio::ip::tcp;            // from <boost/asio/ip/tcp.hpp>

namespace {

// Request bodies above this are rejected (design spec 4.5: frames <= 64 KiB
// applies to HTTP bodies the same way it applies to WebSocket frames).
constexpr std::size_t kMaxRequestBodyBytes = 64UL * 1024UL;
constexpr int kStatusUnauthorized = 401;
constexpr int kStatusInternalServerError = 500;
// Read chunk sizes: normal requests fill a small buffer; uploads use a
// bigger one (each chunk goes straight to disk + digest).
constexpr std::size_t kBodyReadChunkBytes = 8UL * 1024UL;
constexpr std::size_t kUploadReadChunkBytes = 64UL * 1024UL;
constexpr std::size_t kUploadIdBytes = 16;
constexpr unsigned kHttpVersion11 = 11;
constexpr const char *kFilesPath = "/api/v1/files";

auto unauthorized() -> HttpResponse {
    return {kStatusUnauthorized, R"({"error":"unauthorized"})"};
}

auto internalError() -> HttpResponse {
    return {kStatusInternalServerError, R"({"error":"internal_error"})"};
}

// The path without its query string.
auto pathOf(const std::string &target) -> std::string {
    const auto queryStart = target.find('?');
    return queryStart == std::string::npos ? target
                                           : target.substr(0, queryStart);
}

// The declared body size, nullopt when the request carries no usable
// Content-Length (absent, malformed or chunked). Digit values beyond the
// int64 range saturate - the caller's cap check answers 413 for them.
auto contentLengthOf(const http::request<http::buffer_body> &received)
    -> std::optional<std::int64_t> {
    if (!received.contains(http::field::content_length)) {
        return std::nullopt;
    }
    const auto text = received.at(http::field::content_length);
    if (text.empty()) {
        return std::nullopt;
    }
    constexpr std::int64_t kDecimalBase = 10;
    constexpr std::int64_t kMaxSafeFactor =
        std::numeric_limits<std::int64_t>::max() / kDecimalBase;
    std::int64_t value = 0;
    for (const char digit : text) {
        if (digit < '0' || digit > '9') {
            return std::nullopt;
        }
        if (value > kMaxSafeFactor) {
            return std::numeric_limits<std::int64_t>::max();
        }
        value = (value * kDecimalBase) + (digit - '0');
    }
    return value;
}

} // namespace

// One HTTPS connection: handshake, read one request (headers first, then
// the body chunk-by-chunk), dispatch or stream, answer, shutdown - or, for
// GET /ws, authenticate and hand the stream to a WebSocket session. Lives
// on a strand (the accept call passes one), so a future multi-threaded
// io_context cannot interleave this session's handlers.
class Listener::Session : public std::enable_shared_from_this<Session> {
  public:
    Session(tcp::socket socket, ssl::context &sslContext, Router &router,
            const WsHooks *wsHooks, const UploadHooks *uploadHooks)
        : stream_(std::move(socket), sslContext), router_(router),
          wsHooks_(wsHooks), uploadHooks_(uploadHooks) {
        beast::error_code ignored;
        const auto endpoint =
            stream_.next_layer().socket().remote_endpoint(ignored);
        if (!ignored) {
            address_ = endpoint.address().to_string();
        }
    }

    void start() {
        stream_.async_handshake(ssl::stream_base::server,
                                beast::bind_front_handler(&Session::onHandshake,
                                                          shared_from_this()));
    }

  private:
    void onHandshake(beast::error_code errorCode) {
        if (errorCode) {
            return; // failed TLS handshake: the connection is done
        }
        // Headers first: the upload path must stream its body instead of
        // buffering it, and only the headers tell the two apart.
        http::async_read_header(
            stream_, buffer_, parser_,
            beast::bind_front_handler(&Session::onHeader, shared_from_this()));
    }

    void onHeader(beast::error_code errorCode, std::size_t /*bytes*/) {
        if (errorCode) {
            return;
        }
        const auto &received = parser_.get();
        request_.method = received.method_string();
        request_.target = received.target();
        if (received.contains(http::field::authorization)) {
            request_.authorization = received.at(http::field::authorization);
        }
        request_.address = address_;
        request_.contentLength = contentLengthOf(received);
        version_ = received.version();

        // PUT /api/v1/files streams (Plan 3 Task 8); everything else
        // buffers its (<= 64 KiB) body into memory.
        if (uploadHooks_ != nullptr && request_.method == "PUT" &&
            pathOf(request_.target) == kFilesPath) {
            startUpload();
            return;
        }
        parser_.body_limit(kMaxRequestBodyBytes);
        readBodyChunk();
    }

    // The normal path: accumulate the body until the parser is done.
    void readBodyChunk() {
        if (parser_.is_done()) {
            onFullRequest();
            return;
        }
        bodyChunk_.resize(kBodyReadChunkBytes);
        parser_.get().body().data = bodyChunk_.data();
        parser_.get().body().size = bodyChunk_.size();
        http::async_read_some(stream_, buffer_, parser_,
                              beast::bind_front_handler(&Session::onBodyChunk,
                                                        shared_from_this()));
    }

    void onBodyChunk(beast::error_code errorCode, std::size_t /*bytes*/) {
        // A full chunk buffer surfaces as need_buffer: the octets are
        // already in the chunk prefix, so the read continues.
        if (errorCode == http::error::need_buffer) {
            errorCode = {};
        }
        if (errorCode) {
            return; // broken body or body_limit exceeded: drop the peer
        }
        // buffer_body consumed capacity - body().size bytes; the rest of
        // the chunk now holds body octets.
        const auto filled = bodyChunk_.size() - parser_.get().body().size;
        body_.append(bodyChunk_.data(), filled);
        readBodyChunk();
    }

    void onFullRequest() {
        const auto startedAt = std::chrono::steady_clock::now();
        request_.body = body_;

        if (handleWebSocketUpgrade()) {
            return; // the TLS stream was moved into the WebSocket session
        }

        const HttpResponse response = router_.dispatch(request_);
        const auto durationMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startedAt)
                .count();
        logRequest(request_.address, request_.method, request_.target,
                   response.status, durationMs);
        respond(response, version_);
    }

    // GET /ws: authenticate the bearer token, then hand the TLS stream to a
    // WebSocket session (true = the stream was taken over and the HTTP path
    // must stop). Returns false for non-WS targets.
    auto handleWebSocketUpgrade() -> bool {
        const auto path = pathOf(request_.target);
        if (path != "/ws" || request_.method != "GET") {
            return false;
        }
        auto self = shared_from_this();
        const auto device = wsHooks_ != nullptr
                                ? wsHooks_->authenticate(request_.authorization)
                                : std::optional<Device>();
        if (!device.has_value()) {
            respond(unauthorized(), version_);
            return true;
        }
        // WsSession keeps its own copy of the upgrade request (a string
        // body one); the buffer_body parser never buffered a body here
        // anyway (GET /ws has none).
        auto session = std::make_shared<WsSession>(
            WsSession::Stream(std::move(stream_)), upgradeRequest(), *device,
            wsHooks_->limits, wsHooks_->nowMs, *wsHooks_->hub,
            *wsHooks_->callSink, *wsHooks_->msgSink);
        session->run();
        return true;
    }

    // The GET /ws upgrade request as a string_body message (WsSession's
    // shape): same method, target, version and fields, no body.
    [[nodiscard]] auto upgradeRequest() const
        -> http::request<http::string_body> {
        const auto &received = parser_.get();
        http::request<http::string_body> copy{
            received.method(), received.target(), received.version()};
        for (const auto &field : received) {
            copy.set(field.name_string(), field.value());
        }
        return copy;
    }

    // The upload path (Plan 3 Task 8): header-level checks (401/411/413/
    // 507), then stream the body chunk-by-chunk into the FileStore with an
    // on-the-fly digest, then record the row and answer 201.
    void startUpload() {
        const auto device = authenticateBearer(*uploadHooks_->store, request_);
        if (!device.has_value()) {
            respond(unauthorized(), version_);
            return;
        }
        const auto error = checkUploadHeaders(
            *uploadHooks_->store, uploadHooks_->limits, device->user, request_);
        if (error.has_value()) {
            respond(*error, version_);
            return;
        }
        uploadOwner_ = device->user;
        uploadId_ = randomHex(kUploadIdBytes);
        uploadWriter_ = uploadHooks_->files->beginWrite(uploadId_);
        if (uploadWriter_ == nullptr) {
            respond(internalError(), version_);
            return;
        }
        // A client that declares a small Content-Length and streams more is
        // answered with a dropped connection (the 413 answer is reserved
        // for an honest header-level rejection).
        parser_.body_limit(uploadHooks_->limits.maxFileBytes);
        readUploadChunk();
    }

    void readUploadChunk() {
        if (parser_.is_done()) {
            finishUploadNow();
            return;
        }
        uploadChunk_.resize(kUploadReadChunkBytes);
        parser_.get().body().data = uploadChunk_.data();
        parser_.get().body().size = uploadChunk_.size();
        http::async_read_some(stream_, buffer_, parser_,
                              beast::bind_front_handler(&Session::onUploadChunk,
                                                        shared_from_this()));
    }

    void onUploadChunk(beast::error_code errorCode, std::size_t /*bytes*/) {
        // A full chunk buffer surfaces as need_buffer: keep streaming.
        if (errorCode == http::error::need_buffer) {
            errorCode = {};
        }
        if (errorCode) {
            // body_limit exceeded or a broken stream: the partial file is
            // discarded and the connection dropped without a response.
            uploadWriter_.reset();
            return;
        }
        const auto filled = uploadChunk_.size() - parser_.get().body().size;
        if (filled > 0 && !uploadWriter_->feed(
                              std::string_view(uploadChunk_.data(), filled))) {
            uploadWriter_.reset(); // disk failure: drop, no response
            return;
        }
        readUploadChunk();
    }

    void finishUploadNow() {
        const auto sha256Hex = uploadWriter_->finish();
        const auto bytes = static_cast<std::int64_t>(uploadWriter_->bytesFed());
        uploadWriter_.reset();
        if (sha256Hex.empty()) {
            respond(internalError(), version_);
            return;
        }
        respond(finishUpload(*uploadHooks_->store, uploadOwner_,
                             *uploadHooks_->files, uploadId_, bytes, sha256Hex,
                             uploadHooks_->nowMs()),
                version_);
    }

    void respond(const HttpResponse &response, unsigned httpVersion) {
        if (!response.fileForStreaming.empty()) {
            respondFile(response, httpVersion);
            return;
        }
        auto message = std::make_shared<http::response<http::string_body>>(
            static_cast<http::status>(response.status), httpVersion);
        message->body() = response.body;
        message->keep_alive(false);
        message->prepare_payload();
        auto self = shared_from_this();
        http::async_write(stream_, *message,
                          [self, message](beast::error_code writeError,
                                          std::size_t /*bytes*/) -> void {
                              if (writeError) {
                                  return;
                              }
                              // Graceful TLS shutdown ends the one-request
                              // connection. The shutdown continuation owns the
                              // session: releasing it here is what destroys
                              // stream_ - without the capture the session would
                              // die while the shutdown op is still pending.
                              self->stream_.async_shutdown(
                                  [self](const beast::error_code &) -> void {});
                          });
    }

    // A file download (Plan 3 Task 8): the response body is the stored
    // file's bytes, streamed from disk by Beast's file_body; the digest
    // rides in X-Linko-Sha256.
    void respondFile(const HttpResponse &response, unsigned httpVersion) {
        auto self = shared_from_this();
        auto message = std::make_shared<http::response<http::file_body>>(
            static_cast<http::status>(response.status), httpVersion);
        beast::error_code fileError;
        message->body().open(response.fileForStreaming.c_str(),
                             beast::file_mode::read, fileError);
        if (fileError) {
            respond(internalError(), httpVersion);
            return;
        }
        message->set(http::field::content_type, "application/octet-stream");
        if (!response.fileSha256.empty()) {
            message->set("X-Linko-Sha256", response.fileSha256);
        }
        message->keep_alive(false);
        message->prepare_payload();
        http::async_write(stream_, *message,
                          [self, message](beast::error_code writeError,
                                          std::size_t /*bytes*/) -> void {
                              if (writeError) {
                                  return;
                              }
                              self->stream_.async_shutdown(
                                  [self](const beast::error_code &) -> void {});
                          });
    }

    beast::ssl_stream<beast::tcp_stream> stream_;
    std::string address_;
    beast::flat_buffer buffer_;
    http::request_parser<http::buffer_body> parser_;
    HttpRequest request_; // headers first, body filled when buffered
    std::string body_;
    std::vector<char> bodyChunk_;
    std::vector<char> uploadChunk_;
    std::unique_ptr<Writer> uploadWriter_;
    std::string uploadId_;
    std::string uploadOwner_;
    unsigned version_ = kHttpVersion11;
    Router &router_;
    const WsHooks *wsHooks_;
    const UploadHooks *uploadHooks_;
};

Listener::Listener(asio::io_context &ioContext, ssl::context &sslContext,
                   Router &router, const WsHooks *wsHooks,
                   const UploadHooks *uploadHooks)
    : ioContext_(ioContext), wsHooks_(wsHooks), uploadHooks_(uploadHooks),
      sslContext_(sslContext), router_(router) {}

void Listener::listen(const std::string &bindAddress, unsigned short port) {
    acceptor_ = std::make_unique<tcp::acceptor>(ioContext_);
    const tcp::endpoint endpoint(asio::ip::make_address(bindAddress), port);
    acceptor_->open(endpoint.protocol());
    acceptor_->set_option(asio::socket_base::reuse_address(true));
    acceptor_->bind(endpoint);
    acceptor_->listen(asio::socket_base::max_listen_connections);
    doAccept();
}

auto Listener::port() const -> unsigned short {
    return acceptor_->local_endpoint().port();
}

void Listener::doAccept() {
    // The executor overload builds each accepted socket (and therefore the
    // session) on its own strand.
    acceptor_->async_accept(
        asio::make_strand(ioContext_),
        [this](beast::error_code errorCode, tcp::socket socket) -> void {
            if (!errorCode) {
                auto session =
                    std::make_shared<Session>(std::move(socket), sslContext_,
                                              router_, wsHooks_, uploadHooks_);
                session->start();
            }
            doAccept();
        });
}

} // namespace server
