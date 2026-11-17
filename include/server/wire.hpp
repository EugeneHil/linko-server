// Wire helpers (Plan 3 Task 5): server-side envelope construction and
// serialization. Envelope ids come from the server's single random source
// (randomHex); timestamps come from the caller's clock.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "linko/envelope.hpp"

namespace server {

// A fresh envelope of `type` with `body`: v = protocol version, id =
// randomHex(16), ts = `nowMs`. Unknown types are rejected downstream by the
// parser, so callers pass type names from linko's kType* constants.
[[nodiscard]] auto makeEnvelope(std::string_view type, nlohmann::json body,
                                std::int64_t nowMs) -> linko::Envelope;

// Serializes an envelope to the wire format (linko::serialize).
[[nodiscard]] auto toWire(const linko::Envelope &envelope) -> std::string;

} // namespace server
