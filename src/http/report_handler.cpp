// Call reports endpoint (Plan 3 Task 9): POST /api/v1/calls/{callId}/report
// stores the client's end-of-call quality summary verbatim (design spec 4.5)
// behind Bearer authentication. The report body is app-defined; the handler
// only gates it: it must be a JSON object of at most 8 KiB.
#include "server/http.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace server {

namespace {

constexpr int kStatusNoContent = 204;
constexpr int kStatusUnauthorized = 401;
constexpr int kStatusBadRequest = 400;
constexpr int kStatusNotFound = 404;
constexpr std::size_t kMaxReportBytes = 8192;
constexpr std::string_view kRoutePrefix = "/api/v1/calls/";
constexpr std::string_view kRouteSuffix = "/report";

auto unauthorized() -> HttpResponse {
    return {kStatusUnauthorized, R"({"error":"unauthorized"})"};
}

auto notFound() -> HttpResponse {
    return {kStatusNotFound, R"({"error":"not_found"})"};
}

// The {callId} segment of a POST /api/v1/calls/{callId}/report target.
// Anything else (missing id, nested segments, stray shapes) is unknown-route
// territory, answered with 404.
auto reportCallIdOf(const std::string &target) -> std::string {
    const auto queryStart = target.find('?');
    const auto path =
        queryStart == std::string::npos ? target : target.substr(0, queryStart);
    if (path.size() <= kRoutePrefix.size() + kRouteSuffix.size() ||
        path.compare(0, kRoutePrefix.size(), kRoutePrefix) != 0 ||
        path.compare(path.size() - kRouteSuffix.size(), kRouteSuffix.size(),
                     kRouteSuffix) != 0) {
        return "";
    }
    auto callId =
        path.substr(kRoutePrefix.size(),
                    path.size() - kRoutePrefix.size() - kRouteSuffix.size());
    if (callId.empty() || callId.find('/') != std::string::npos) {
        return "";
    }
    return callId;
}

} // namespace

auto handleCallReport(Store &store, const HttpRequest &request,
                      std::int64_t nowMs) -> HttpResponse {
    const auto device = authenticateBearer(store, request);
    if (!device.has_value()) {
        return unauthorized();
    }
    const auto callId = reportCallIdOf(request.target);
    if (callId.empty()) {
        return notFound();
    }
    if (request.body.size() > kMaxReportBytes) {
        return {kStatusBadRequest, R"({"error":"report_too_large"})"};
    }
    const auto parsed = nlohmann::json::parse(request.body, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        return {kStatusBadRequest, R"({"error":"invalid_report"})"};
    }
    store.addCallReport(
        CallReportRow{callId, device->user, nowMs, request.body});
    return {kStatusNoContent, ""};
}

} // namespace server
