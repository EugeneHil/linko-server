// Wire helpers implementation (Plan 3 Task 5).
#include "server/wire.hpp"

#include "server/crypto.hpp"

namespace server {

auto makeEnvelope(std::string_view type, nlohmann::json body,
                  std::int64_t nowMs) -> linko::Envelope {
    constexpr std::size_t kEnvelopeIdBytes = 16;
    return linko::Envelope{
        linko::kCurrentVersion,
        std::string(type),
        randomHex(kEnvelopeIdBytes),
        nowMs,
        std::move(body),
    };
}

auto toWire(const linko::Envelope &envelope) -> std::string {
    return linko::serialize(envelope);
}

} // namespace server
