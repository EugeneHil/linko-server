// Bearer authentication + GET /api/v1/users (Plan 3 Task 5): token-hash
// lookup for every authenticated endpoint, username prefix search for
// contact discovery (max 20 matches, sorted).
#include "server/http.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "linko/sha256.hpp"

namespace server {

namespace {

constexpr int kStatusUnauthorized = 401;
constexpr std::size_t kMaxUserMatches = 20;
constexpr int kStatusOk = 200;

auto unauthorized() -> HttpResponse {
    return {kStatusUnauthorized, R"({"error":"unauthorized"})"};
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto queryParameter(const std::string &target, const std::string &name)
    -> std::string {
    const auto queryStart = target.find('?');
    if (queryStart == std::string::npos) {
        return "";
    }
    const auto query = target.substr(queryStart + 1);
    const auto start = query.find(name + "=");
    if (start == std::string::npos) {
        return "";
    }
    const auto valueStart = start + name.size() + 1;
    const auto valueEnd = query.find('&', valueStart);
    return query.substr(valueStart, valueEnd == std::string::npos
                                        ? std::string::npos
                                        : valueEnd - valueStart);
}

} // namespace

// Bearer <device token> -> the live device behind it (nullopt otherwise).
// Tokens are stored hashed; the hash comparison is the authentication.
auto authenticateBearer(Store &store, const HttpRequest &request)
    -> std::optional<Device> {
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (request.authorization.size() <= kBearerPrefix.size() ||
        request.authorization.compare(0, kBearerPrefix.size(), kBearerPrefix) !=
            0) {
        return std::nullopt;
    }
    const auto token = request.authorization.substr(kBearerPrefix.size());
    const auto tokenHash =
        linko::sha256Hex(std::vector<std::uint8_t>(token.begin(), token.end()));
    return store.deviceByTokenHash(tokenHash);
}

auto handleUsers(Store &store, const HttpRequest &request) -> HttpResponse {
    if (!authenticateBearer(store, request).has_value()) {
        return unauthorized();
    }
    const auto prefix = queryParameter(request.target, "prefix");
    std::vector<std::string> matches;
    for (const auto &user : store.listUsers()) {
        if (user.rfind(prefix, 0) == 0) {
            matches.push_back(user);
            if (matches.size() == kMaxUserMatches) {
                break;
            }
        }
    }
    return {kStatusOk, nlohmann::json{{"users", matches}}.dump()};
}

} // namespace server
