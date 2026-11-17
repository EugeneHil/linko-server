// GET /api/v1/turn (Plan 3 Task 5 + spec 4.6): short-lived TURN REST
// credentials. username = "<unix-expiry>:<user>", credential =
// base64(HMAC-SHA1(turnSecret, username)). The shared secret never leaves
// the host; apps receive only these derived credentials.
#include "server/http.hpp"

#include <array>
#include <chrono>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace server {

namespace {

constexpr int kStatusUnauthorized = 401;
constexpr int kStatusNotConfigured = 500;
constexpr int kBase64BufferSize = 64;
constexpr int kStatusOk = 200;

auto unauthorized() -> HttpResponse {
    return {kStatusUnauthorized, R"({"error":"unauthorized"})"};
}

} // namespace

auto handleTurn(const Config &config, Store &store, const HttpRequest &request)
    -> HttpResponse {
    const auto device = authenticateBearer(store, request);
    if (!device.has_value()) {
        return unauthorized();
    }
    if (config.turnSecret.empty()) {
        return {kStatusNotConfigured, R"({"error":"turn_not_configured"})"};
    }

    const auto nowSeconds =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    const auto expiry = nowSeconds + config.limits.turnTtlSec;
    const auto username = std::to_string(expiry) + ":" + device->user;

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;
    static_cast<void>(
        HMAC(EVP_sha1(), config.turnSecret.data(),
             static_cast<int>(config.turnSecret.size()),
             reinterpret_cast<const unsigned char *>(username.data()),
             static_cast<int>(username.size()), digest.data(), &digestLength));
    std::array<unsigned char, kBase64BufferSize> encoded{};
    const int encodedLength = EVP_EncodeBlock(encoded.data(), digest.data(),
                                              static_cast<int>(digestLength));
    const auto credential =
        std::string(reinterpret_cast<const char *>(encoded.data()),
                    static_cast<std::size_t>(encodedLength));

    return {
        kStatusOk,
        nlohmann::json{
            {"username", username},
            {"credential", credential},
            {"ttlSec", config.limits.turnTtlSec},
            {"urls", config.turnUris},
        }
            .dump(),
    };
}

} // namespace server
