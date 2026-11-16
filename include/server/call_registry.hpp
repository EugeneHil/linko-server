// Call registry (design spec 4.5, Plan 3 Task 6): one core CallState machine
// per call, fed from the caller's perspective - the caller's call.invite
// feeds LocalInvite, and every message from the callee feeds the Remote*
// event of the plan's wire-to-event table (call.ringing, call.accept,
// call.reject, call.busy; call.cancel and call.hangup as Remote* from the
// callee and LocalCancel / LocalHangup from the caller, who emits neither
// call.accept nor Remote* actions). The registry answers busy invites, runs
// the ring timeout, relays signaling between the two parties and cleans up
// when a socket drops.
//
// Host mapping notes (the machine's effects carry no callId):
// - every effect is addressed to the entry whose machine produced it;
// - SendMessage forwards the original wire bytes of the envelope that
//   triggered the transition (peer-authored bodies are relayed through
//   parse + serialize, never rebuilt); the server-built envelopes are the
//   two the registry itself owns: call.cancel to the callee on a ring
//   timeout and call.hangup to the peer when a socket drops;
// - StartTimer / CancelTimer address the ring (kRingTimeoutMs) or connect
//   (kConnectTimeoutMs) budget of that same entry; kReconnectTimeoutMs
//   never fires here (client-side only);
// - the CallKit / ringing / ICE-restart effects are client-side and ignored.
//
// Relay rules: call.offer / call.answer / call.ice / call.ice-restart and
// file.* are forwarded without machine input (the server never sees ICE
// state); call.ringing is forwarded while the machine is still ringing;
// accept, reject, busy and cancel are forwarded exactly when the machine
// accepted the event, so a duplicate accept is forwarded once and a late
// hangup after the call ended is dropped; call.hangup is definitive intent
// from either side and is forwarded from any live state, ending the entry.
//
// The machine's connect budget needs one registry-side caveat: the server
// never sees IceConnected, so its machine stays in Connecting after an
// accept and would end on the 20 s connect timer even though both clients
// may well have connected. When that timer expires the entry therefore
// survives as a relay-only route - participant-gated forwarding until the
// next definitive end message or a socket drop removes it. Dropping the
// entry outright would silence every call that outlives the connect budget,
// including the hangup that ends it. Its machine state (Ended) keeps such a
// call out of busy detection; a truly failed call leaves both clients Idle,
// and the clients' own glare resolution guards any residual double-call.
//
// Malformed typed bodies are dropped silently: the session already gates
// envelope shape, and core's toBody() always builds valid bodies, so only a
// hostile client can produce one.
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

#include "linko/call_state_machine.hpp"
#include "linko/envelope.hpp"
#include "server/config.hpp"
#include "server/hub.hpp"
#include "server/ws_session.hpp"

namespace server {

class CallRegistry final : public ProtocolSink {
  public:
    using Clock = std::function<std::int64_t()>; // epoch milliseconds

    // `limits` carries the file.offer size cap (Plan 3 Task 8): an offer
    // above Limits::maxFileBytes never relays - the sender gets
    // session.error{code:"file_too_large"}.
    CallRegistry(Hub &hub, const Limits &limits, Clock nowMs,
                 asio::any_io_executor timers);
    ~CallRegistry() override = default;
    CallRegistry(const CallRegistry &) = delete;
    auto operator=(const CallRegistry &) -> CallRegistry & = delete;

    void onEnvelope(const std::string &fromUser,
                    const linko::Envelope &envelope,
                    std::int64_t deviceId) override;
    void onSocketDrop(const std::string &user) override;

  private:
    // One tracked call: the caller-perspective machine, the two usernames
    // and the poll timers for the ring and connect budgets.
    struct Call {
        linko::CallState state;
        std::string caller;
        std::string callee;
        std::optional<asio::steady_timer> ring;
        std::optional<asio::steady_timer> connect;
        std::int64_t ringDeadlineMs = 0;
        std::int64_t connectDeadlineMs = 0;
    };

    enum class Which : std::uint8_t { Ring, Connect };

    void handleInvite(const std::string &fromUser,
                      const linko::Envelope &envelope, const std::string &wire);
    void handleLifecycle(const std::string &fromUser,
                         const linko::Envelope &envelope,
                         const std::string &wire);
    // The file.offer size cap: true when the offer exceeded the limit and
    // the sender was answered with session.error{file_too_large} (nothing
    // is relayed); false when the offer may pass through.
    [[nodiscard]] auto handleOfferCap(const std::string &fromUser,
                                      const linko::Envelope &envelope) -> bool;
    void handlePassThrough(const std::string &fromUser,
                           const linko::Envelope &envelope,
                           const std::string &wire);
    void runTimerEffects(Call &call, const std::vector<linko::Effect> &effects);
    void armTimer(const std::string &callId, Call &call, Which which,
                  int timeoutMs);
    void onTimerTick(const std::string &callId, Which which);
    void relay(const std::string &peer, const std::string &wire);
    void sendEnvelope(const std::string &user, const linko::Envelope &envelope);
    [[nodiscard]] auto isBusy(const std::string &user) const -> bool;
    [[nodiscard]] static auto peerOf(const Call &call, const std::string &user)
        -> std::string;

    Hub &hub_;
    Limits limits_;
    Clock nowMs_;
    asio::any_io_executor executor_;
    // Sessions run on per-connection strands and the timers run on the shared
    // io_context, so the map is guarded; hub.send is leaf-locked itself.
    std::mutex mutex_;
    std::unordered_map<std::string, Call> calls_;
};

} // namespace server
