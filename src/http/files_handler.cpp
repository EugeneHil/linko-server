// File endpoints (Plan 3 Task 8): the download handler and the upload
// header/completion phases live here; the streaming loop itself runs in the
// listener. Bearer authentication and the 404 semantics are shared with the
// other authenticated endpoints.
#include "server/http.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace server {

namespace {

constexpr int kStatusOk = 200;
constexpr int kStatusCreated = 201;
constexpr int kStatusUnauthorized = 401;
constexpr int kStatusNotFound = 404;
constexpr int kStatusLengthRequired = 411;
constexpr int kStatusPayloadTooLarge = 413;
constexpr int kStatusInsufficientStorage = 507;
constexpr std::size_t kUploadIdHexChars = 32;

auto unauthorized() -> HttpResponse {
    return {kStatusUnauthorized, R"({"error":"unauthorized"})"};
}

auto notFound() -> HttpResponse {
    return {kStatusNotFound, R"({"error":"not_found"})"};
}

// The id segment of a GET /api/v1/files/{id} target: upload ids are
// randomHex(16) - 32 lowercase hex characters. Anything else (including
// traversal shapes) is unknown-file territory, answered with 404.
auto fileIdOf(const std::string &target) -> std::string {
    constexpr std::string_view kPrefix = "/api/v1/files/";
    const auto queryStart = target.find('?');
    const auto path =
        queryStart == std::string::npos ? target : target.substr(0, queryStart);
    if (path.size() <= kPrefix.size() ||
        path.compare(0, kPrefix.size(), kPrefix) != 0) {
        return "";
    }
    auto fileId = path.substr(kPrefix.size());
    if (fileId.size() != kUploadIdHexChars ||
        fileId.find_first_not_of("0123456789abcdef") != std::string::npos) {
        return "";
    }
    return fileId;
}

} // namespace

auto handleFileDownload(Store &store, FileStore &files,
                        const HttpRequest &request) -> HttpResponse {
    if (!authenticateBearer(store, request).has_value()) {
        return unauthorized();
    }
    auto fileId = fileIdOf(request.target);
    if (fileId.empty()) {
        return notFound();
    }
    const auto row = store.fileInfo(fileId);
    if (!row.has_value()) {
        return notFound();
    }
    // The bytes may be gone (TTL cleanup raced the row, or a crash left the
    // row behind): without them there is nothing to download.
    auto file = files.open(fileId);
    if (!file.is_open()) {
        return notFound();
    }
    file.close();
    HttpResponse response{kStatusOk, ""};
    response.fileForStreaming = row->path;
    response.fileSha256 = row->sha256;
    return response;
}

auto checkUploadHeaders(Store &store, const Limits &limits,
                        const std::string &owner, const HttpRequest &request)
    -> std::optional<HttpResponse> {
    if (!request.contentLength.has_value()) {
        return HttpResponse{kStatusLengthRequired,
                            R"({"error":"length_required"})"};
    }
    if (*request.contentLength > limits.maxFileBytes) {
        return HttpResponse{kStatusPayloadTooLarge,
                            R"({"error":"file_too_large"})"};
    }
    const auto used = store.quotaUsed(owner);
    const auto offered = static_cast<std::uint64_t>(*request.contentLength);
    if (used + offered > static_cast<std::uint64_t>(limits.userQuotaBytes)) {
        return HttpResponse{kStatusInsufficientStorage,
                            R"({"error":"quota_exceeded"})"};
    }
    return std::nullopt;
}

auto finishUpload(Store &store, const std::string &owner, FileStore &files,
                  const std::string &fileId, std::int64_t size,
                  const std::string &sha256Hex, std::int64_t nowMs)
    -> HttpResponse {
    store.addFile(
        FileRow{fileId, owner, size, sha256Hex, nowMs, files.pathOf(fileId)});
    return {kStatusCreated,
            nlohmann::json{
                {"fileId", fileId},
                {"sha256", sha256Hex},
                {"size", size},
            }
                .dump()};
}

} // namespace server
