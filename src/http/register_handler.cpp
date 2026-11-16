// Registration endpoint (Plan 3 Task 4): POST /api/v1/register. The invite
// code and the device token are the only secrets on this path; the token is
// returned once in the 201 body and stored as a SHA-256 hex digest only.
#include "server/http.hpp"

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "linko/sha256.hpp"
#include "server/crypto.hpp"

namespace server {
namespace {

constexpr std::size_t kMaxUsernameLength = 32;
constexpr std::size_t kTokenBytes = 32;

constexpr int kStatusBadRequest = 400;
constexpr int kStatusForbidden = 403;
constexpr int kStatusCreated = 201;
constexpr int kStatusServerError = 500;
constexpr int kStatusTooManyAttempts = 429;

auto isValidUsername(const std::string &name) -> bool {
    if (name.empty() || name.size() > kMaxUsernameLength) {
        return false;
    }
    const auto allowed = [](char character) -> bool {
        return (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') || character == '_' ||
               character == '.' || character == '-';
    };
    return std::all_of(name.begin(), name.end(), allowed);
}

auto jsonError(int status, const std::string &code) -> HttpResponse {
    return {status, nlohmann::json{{"error", code}}.dump()};
}

} // namespace

auto handleRegister(Store &store, Throttle &throttle,
                    const HttpRequest &request) -> HttpResponse {
    // The address budget counts every attempt (design spec 4.5:
    // failed-auth throttling per address); successes are rare in v0.1's
    // two-device world, so a shared budget keeps the rule simple.
    if (!throttle.allow(request.address)) {
        return jsonError(kStatusTooManyAttempts, "too_many_attempts");
    }

    nlohmann::json parsed = nlohmann::json::parse(request.body, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object() ||
        !parsed.contains("code") || !parsed.contains("username") ||
        !parsed.at("code").is_string() || !parsed.at("username").is_string()) {
        return jsonError(kStatusBadRequest, "invalid_request");
    }
    const auto code = parsed.at("code").get<std::string>();
    const auto username = parsed.at("username").get<std::string>();
    if (!isValidUsername(username)) {
        return jsonError(kStatusBadRequest, "invalid_username");
    }
    if (store.consumeInvite(code, username) != InviteResult::Ok) {
        return jsonError(kStatusForbidden, "invalid_invite");
    }

    const auto token = randomHex(kTokenBytes);
    const auto tokenHash =
        linko::sha256Hex(std::vector<std::uint8_t>(token.begin(), token.end()));
    const auto result = store.registerDevice(
        username, tokenHash,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    if (result.device.id == 0) {
        return jsonError(kStatusServerError, "registration_failed");
    }
    return {
        kStatusCreated,
        nlohmann::json{
            {"user", username},
            {"device", result.device.id},
            {"token", token},
        }
            .dump(),
    };
}

} // namespace server
