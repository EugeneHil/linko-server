// Structured logging (design spec 6 "Server logs"): the request line is
// exactly "addr method path status duration_ms" with the query string
// stripped; event lines carry a short what and detail. The sink is
// swappable so tests capture lines; the default sink writes to stderr.
// Never log tokens, invite codes, Authorization values, message bodies,
// SDP or ICE credentials - callers format the lines, so the rule lives at
// every call site.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace server {

using LogSink = std::function<void(const std::string &line)>;

// Replaces the log sink; nullptr restores the default stderr sink.
void setLogSink(LogSink sink);

// One HTTP request: "addr method path status duration_ms", query stripped.
void logRequest(const std::string &address, const std::string &method,
                const std::string &path, int status, std::int64_t durationMs);

// One operational event: "<what> <detail>" (no secrets in either).
void logEvent(const std::string &what, const std::string &detail);

} // namespace server
