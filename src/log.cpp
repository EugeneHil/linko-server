// Log implementation (Plan 3 Task 2).
#include "server/log.hpp"

#include <cstdio>
#include <mutex>
#include <utility>

namespace server {
namespace {

std::mutex sinkMutex;

auto sink() -> LogSink & {
    static LogSink value;
    return value;
}

void emit(const std::string &line) {
    const std::scoped_lock<std::mutex> lock(sinkMutex);
    if (sink()) {
        sink()(line);
        return;
    }
    std::fputs((line + "\n").c_str(), stderr);
}

} // namespace

void setLogSink(LogSink newSink) {
    const std::scoped_lock<std::mutex> lock(sinkMutex);
    sink() = std::move(newSink);
}

// The call-site order is fixed by the interface in the plan (address,
// method, path, ...).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void logRequest(const std::string &address, const std::string &method,
                const std::string &path, int status, std::int64_t durationMs) {
    // The query string never reaches the log (design spec 6: address,
    // method, path without query, status, duration).
    const auto queryStart = path.find('?');
    const auto pathOnly =
        queryStart == std::string::npos ? path : path.substr(0, queryStart);
    emit(address + " " + method + " " + pathOnly + " " +
         std::to_string(status) + " " + std::to_string(durationMs));
}

void logEvent(const std::string &what, const std::string &detail) {
    emit(what + " " + detail);
}

} // namespace server
