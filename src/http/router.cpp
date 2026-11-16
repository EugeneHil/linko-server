// Router implementation (Plan 3 Task 4): exact (method, path) matching,
// query strings stripped before matching, 404/405 semantics.
#include "server/http.hpp"

namespace server {
namespace {

constexpr int kStatusNotFound = 404;
constexpr int kStatusMethodNotAllowed = 405;

// The routing key of a request: method plus the path without its query;
// the (method, target) order is fixed by the interface in the plan.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto routeKey(const std::string &method, const std::string &target)
    -> std::string {
    const auto queryStart = target.find('?');
    const auto path =
        queryStart == std::string::npos ? target : target.substr(0, queryStart);
    return method + " " + path;
}

auto pathOf(const std::string &target) -> std::string {
    const auto queryStart = target.find('?');
    return queryStart == std::string::npos ? target
                                           : target.substr(0, queryStart);
}

} // namespace

void Router::add(const std::string &method, const std::string &path,
                 HttpHandler handler) {
    routes_.emplace_back(method + " " + path, std::move(handler));
    knownPaths_.push_back(path);
}

auto Router::dispatch(const HttpRequest &request) const -> HttpResponse {
    const auto key = routeKey(request.method, request.target);
    for (const auto &[knownKey, handler] : routes_) {
        if (knownKey == key) {
            return handler(request);
        }
    }
    const auto path = pathOf(request.target);
    for (const auto &knownPath : knownPaths_) {
        if (knownPath == path) {
            return {
                kStatusMethodNotAllowed,
                R"({"error":"method_not_allowed"})",
            };
        }
    }
    return {kStatusNotFound, R"({"error":"not_found"})"};
}

} // namespace server
