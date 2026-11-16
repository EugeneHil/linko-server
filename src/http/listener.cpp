// Listener implementation (Plan 3 Task 4): TLS-only Beast accept loop, one
// session per connection on its own strand, one request per connection,
// every completed request logged.
#include "server/http.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "server/log.hpp"

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

} // namespace

// One HTTPS connection: handshake, read one request, dispatch, answer,
// shutdown. Lives on a strand (the accept call passes one), so a future
// multi-threaded io_context cannot interleave this session's handlers.
class Listener::Session : public std::enable_shared_from_this<Session> {
  public:
    Session(tcp::socket socket, ssl::context &sslContext, Router &router)
        : stream_(std::move(socket), sslContext), router_(router) {
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
        parser_ = std::make_shared<http::request_parser<http::string_body>>();
        parser_->body_limit(kMaxRequestBodyBytes);
        http::async_read(
            stream_, buffer_, *parser_,
            beast::bind_front_handler(&Session::onRead, shared_from_this()));
    }

    void onRead(beast::error_code errorCode, std::size_t /*bytesTransferred*/) {
        if (errorCode) {
            return;
        }
        const auto startedAt = std::chrono::steady_clock::now();
        const http::request<http::string_body> &received = parser_->get();

        HttpRequest request;
        request.method = received.method_string();
        request.target = received.target();
        request.body = received.body();
        if (received.contains(http::field::authorization)) {
            request.authorization = received.at(http::field::authorization);
        }
        request.address = address_;

        const HttpResponse response = router_.dispatch(request);
        const auto durationMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startedAt)
                .count();
        logRequest(request.address, request.method, request.target,
                   response.status, durationMs);

        auto message = std::make_shared<http::response<http::string_body>>(
            static_cast<http::status>(response.status), received.version());
        message->body() = response.body;
        message->keep_alive(false);
        message->prepare_payload();
        auto self = shared_from_this();
        http::async_write(
            stream_, *message,
            [self, message](beast::error_code writeError,
                            std::size_t /*bytesTransferred*/) -> void {
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

    beast::ssl_stream<beast::tcp_stream> stream_;
    std::string address_;
    beast::flat_buffer buffer_;
    std::shared_ptr<http::request_parser<http::string_body>> parser_;
    Router &router_;
};

Listener::Listener(asio::io_context &ioContext, ssl::context &sslContext,
                   Router &router)
    : ioContext_(ioContext), sslContext_(sslContext), router_(router) {}

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
                auto session = std::make_shared<Session>(std::move(socket),
                                                         sslContext_, router_);
                session->start();
            }
            doAccept();
        });
}

} // namespace server
