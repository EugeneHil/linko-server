// Call registry implementation (Plan 3 Task 6); see
// include/server/call_registry.hpp for the contract. The map entry is the
// single source of truth for which timers exist; timer callbacks look the
// entry up by callId every tick, so an armed wait that races a disarm or an
// erase simply finds nothing to do.
#include "server/call_registry.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

#include "linko/messages.hpp"
#include "server/wire.hpp"

namespace server {

namespace {

// How often a deadline is checked in wall time; the deadline itself is
// computed on the injected clock, so tests advance time without sleeps
// (same pattern as the session's idle timer). The handler re-reads all
// registry state, so a wait that races a disarm or an erase finds nothing
// to do instead of touching a stale timer.
constexpr std::int64_t kTimerQuantumMs = 100;

} // namespace

CallRegistry::CallRegistry(Hub &hub, const Limits &limits, Clock nowMs,
                           asio::any_io_executor timers)
    : hub_(hub), limits_(limits), nowMs_(std::move(nowMs)),
      executor_(std::move(timers)) {}

void CallRegistry::onEnvelope(const std::string &fromUser,
                              const linko::Envelope &envelope,
                              std::int64_t /*deviceId*/) {
    const auto wire = toWire(envelope);
    const std::scoped_lock lock(mutex_);
    if (envelope.type == linko::kTypeCallInvite) {
        handleInvite(fromUser, envelope, wire);
        return;
    }
    if (envelope.type == linko::kTypeCallRinging ||
        envelope.type == linko::kTypeCallAccept ||
        envelope.type == linko::kTypeCallReject ||
        envelope.type == linko::kTypeCallBusy ||
        envelope.type == linko::kTypeCallCancel ||
        envelope.type == linko::kTypeCallHangup) {
        handleLifecycle(fromUser, envelope, wire);
        return;
    }
    if (envelope.type == linko::kTypeCallOffer ||
        envelope.type == linko::kTypeCallAnswer ||
        envelope.type == linko::kTypeCallIce ||
        envelope.type == linko::kTypeCallIceRestart ||
        envelope.type.rfind("file.", 0) == 0) {
        if (envelope.type == linko::kTypeFileOffer &&
            handleOfferCap(fromUser, envelope)) {
            return;
        }
        handlePassThrough(fromUser, envelope, wire);
    }
}

void CallRegistry::onSocketDrop(const std::string &user) {
    const std::scoped_lock lock(mutex_);
    for (auto entry = calls_.begin(); entry != calls_.end();) {
        auto &call = entry->second;
        if (call.caller != user && call.callee != user) {
            ++entry;
            continue;
        }
        // The machine gets the synthesized RemoteHangup for the record even
        // where it would ignore it (OutgoingRinging); the erase below is
        // what really ends the entry. The peer learns the call is over with
        // a server-built hangup.
        linko::CallEvent event;
        event.kind = linko::CallEvent::RemoteHangup;
        event.callId = entry->first;
        event.peer = peerOf(call, user);
        static_cast<void>(linko::applyEvent(call.state, event));
        const auto peer = peerOf(call, user);
        const auto hangup = makeEnvelope(
            linko::kTypeCallHangup,
            linko::CallEnd{entry->first, std::nullopt}.toBody(), nowMs_());
        call.ring.reset();
        call.connect.reset();
        sendEnvelope(peer, hangup);
        entry = calls_.erase(entry);
    }
}

void CallRegistry::handleInvite(const std::string &fromUser,
                                const linko::Envelope &envelope,
                                const std::string &wire) {
    std::vector<linko::ValidationError> errors;
    const auto invite = linko::CallInvite::fromBody(envelope.body, errors);
    if (!invite.has_value()) {
        return; // malformed body: dropped (see the header comment)
    }
    if (calls_.find(invite->callId) != calls_.end()) {
        return; // a live callId is never re-invited (replay)
    }
    if (isBusy(invite->to)) {
        sendEnvelope(
            fromUser,
            makeEnvelope(linko::kTypeCallBusy,
                         linko::CallEnd{invite->callId, std::nullopt}.toBody(),
                         nowMs_()));
        return;
    }
    linko::CallEvent event;
    event.kind = linko::CallEvent::LocalInvite;
    event.callId = invite->callId;
    event.peer = invite->to;
    event.video = invite->media == "video";
    const auto transition = linko::applyEvent(linko::CallState(), event);
    Call call;
    call.state = transition.next;
    call.caller = fromUser;
    call.callee = invite->to;
    const auto [entry, inserted] =
        calls_.emplace(invite->callId, std::move(call));
    if (!inserted) {
        return;
    }
    // The machine says send the invite (the original wire bytes) and start
    // the ring budget; both effects are addressed to this entry.
    relay(entry->second.callee, wire);
    for (const auto &effect : transition.effects) {
        if (effect.kind == linko::Effect::StartTimer) {
            armTimer(invite->callId, entry->second, Which::Ring,
                     effect.timeoutMs);
        }
    }
}

void CallRegistry::handleLifecycle(const std::string &fromUser,
                                   const linko::Envelope &envelope,
                                   const std::string &wire) {
    // Extract the callId with the typed body parser of the message family.
    std::vector<linko::ValidationError> errors;
    std::string callId;
    if (envelope.type == linko::kTypeCallRinging ||
        envelope.type == linko::kTypeCallAccept) {
        const auto body = linko::CallRef::fromBody(envelope.body, errors);
        if (!body.has_value()) {
            return;
        }
        callId = body->callId;
    } else {
        const auto body = linko::CallEnd::fromBody(envelope.body, errors);
        if (!body.has_value()) {
            return;
        }
        callId = body->callId;
    }
    const auto entry = calls_.find(callId);
    if (entry == calls_.end() || (entry->second.caller != fromUser &&
                                  entry->second.callee != fromUser)) {
        return; // unknown call or a non-participant: dropped
    }
    auto &call = entry->second;
    const bool fromCaller = fromUser == call.caller;

    if (envelope.type == linko::kTypeCallHangup) {
        // Definitive intent from either side: relay from any live state and
        // end the entry. The server's machine stays in Connecting after an
        // accept (it never sees IceConnected), so gating a caller's hangup
        // on a machine transition would drop it.
        call.ring.reset();
        call.connect.reset();
        relay(peerOf(call, fromUser), wire);
        static_cast<void>(calls_.erase(entry));
        return;
    }
    if (envelope.type == linko::kTypeCallRinging) {
        // Progress ping, ignored by the machine by design; relay it only
        // while the call is still ringing so duplicates after accept stop.
        if (call.state.kind == linko::CallStateKind::OutgoingRinging) {
            relay(peerOf(call, fromUser), wire);
        }
        return;
    }

    linko::CallEvent event;
    event.callId = callId;
    if (envelope.type == linko::kTypeCallAccept) {
        event.kind = linko::CallEvent::RemoteAccept;
    } else if (envelope.type == linko::kTypeCallReject) {
        event.kind = linko::CallEvent::RemoteReject;
    } else if (envelope.type == linko::kTypeCallBusy) {
        event.kind = linko::CallEvent::RemoteBusy;
    } else if (fromCaller) {
        event.kind = linko::CallEvent::LocalCancel;
    } else {
        event.kind = linko::CallEvent::RemoteCancel;
    }
    const auto transition = linko::applyEvent(call.state, event);
    if (transition.effects.empty() && transition.next == call.state) {
        return; // duplicate or late: the machine ignored it, so we do too
    }
    call.state = transition.next;
    runTimerEffects(call, transition.effects);
    relay(peerOf(call, fromUser), wire);
    if (call.state.kind == linko::CallStateKind::Ended) {
        call.ring.reset();
        call.connect.reset();
        static_cast<void>(calls_.erase(entry));
    }
}

// The file.offer size cap (Plan 3 Task 8): an offer above the limit never
// reaches the callee - the sender gets session.error{code:"file_too_large"}
// and nothing is forwarded. This also closes the Plan-2 wrap note: at the
// 100 MiB cap, chunkCount = 6400 (16 KiB chunks), far below the uint32
// chunk counter.
auto CallRegistry::handleOfferCap(const std::string &fromUser,
                                  const linko::Envelope &envelope) -> bool {
    std::vector<linko::ValidationError> errors;
    const auto offer = linko::FileOffer::fromBody(envelope.body, errors);
    if (!offer.has_value()) {
        return false; // malformed body: dropped (see the header comment)
    }
    if (offer->manifest.size <=
        static_cast<std::uint64_t>(limits_.maxFileBytes)) {
        return false;
    }
    sendEnvelope(
        fromUser,
        makeEnvelope(linko::kTypeSessionError,
                     linko::SessionError{"file_too_large", ""}.toBody(),
                     nowMs_()));
    return true;
}

void CallRegistry::handlePassThrough(const std::string &fromUser,
                                     const linko::Envelope &envelope,
                                     const std::string &wire) {
    if (!envelope.body.is_object()) {
        return;
    }
    const auto idField = envelope.body.find("callId");
    if (idField == envelope.body.end() || !idField->is_string() ||
        idField->get<std::string>().empty()) {
        return;
    }
    const auto entry = calls_.find(idField->get<std::string>());
    if (entry == calls_.end() || (entry->second.caller != fromUser &&
                                  entry->second.callee != fromUser)) {
        return;
    }
    relay(peerOf(entry->second, fromUser), wire);
}

void CallRegistry::runTimerEffects(Call &call,
                                   const std::vector<linko::Effect> &effects) {
    for (const auto &effect : effects) {
        if (effect.kind == linko::Effect::StartTimer) {
            armTimer(call.state.callId, call,
                     effect.timeoutMs == linko::kRingTimeoutMs ? Which::Ring
                                                               : Which::Connect,
                     effect.timeoutMs);
        } else if (effect.kind == linko::Effect::CancelTimer) {
            if (effect.timeoutMs == linko::kRingTimeoutMs) {
                call.ring.reset();
            } else if (effect.timeoutMs == linko::kConnectTimeoutMs) {
                call.connect.reset();
            }
        }
    }
}

void CallRegistry::armTimer(const std::string &callId, Call &call, Which which,
                            int timeoutMs) {
    if (timeoutMs == linko::kReconnectTimeoutMs) {
        return; // the reconnect budget is client-side only
    }
    auto &timer = which == Which::Ring ? call.ring : call.connect;
    auto &deadline =
        which == Which::Ring ? call.ringDeadlineMs : call.connectDeadlineMs;
    deadline = nowMs_() + timeoutMs;
    timer.emplace(executor_);
    static_cast<void>(
        timer->expires_after(std::chrono::milliseconds(kTimerQuantumMs)));
    // clang-tidy's bugprone-exception-escape treats the asio completion path
    // as a noexcept context; the session's own handlers allocate the same
    // way, and bad_alloc propagates out of io_context::run identically.
    timer->async_wait(
        // NOLINTNEXTLINE(bugprone-exception-escape)
        [this, callId, which](boost::system::error_code error) -> void {
            if (!error) {
                onTimerTick(callId, which);
            }
        });
}

void CallRegistry::onTimerTick(const std::string &callId, Which which) {
    const std::scoped_lock lock(mutex_);
    const auto entry = calls_.find(callId);
    if (entry == calls_.end()) {
        return;
    }
    auto &call = entry->second;
    auto &timer = which == Which::Ring ? call.ring : call.connect;
    if (!timer.has_value()) {
        return; // disarmed between the tick and the handler
    }
    const auto deadline =
        which == Which::Ring ? call.ringDeadlineMs : call.connectDeadlineMs;
    if (nowMs_() < deadline) {
        static_cast<void>(
            timer->expires_after(std::chrono::milliseconds(kTimerQuantumMs)));
        timer->async_wait(
            // NOLINTNEXTLINE(bugprone-exception-escape)
            [this, callId, which](boost::system::error_code error) -> void {
                if (!error) {
                    onTimerTick(callId, which);
                }
            });
        return;
    }
    timer.reset();
    linko::CallEvent event;
    event.kind = which == Which::Ring ? linko::CallEvent::TimerRingExpired
                                      : linko::CallEvent::TimerConnectExpired;
    event.callId = callId;
    const auto transition = linko::applyEvent(call.state, event);
    call.state = transition.next;
    if (which == Which::Ring) {
        // The callee's own machine reports Missed without messaging anyone,
        // so the registry itself tells the callee the call is over.
        sendEnvelope(call.callee,
                     makeEnvelope(linko::kTypeCallCancel,
                                  linko::CallEnd{callId, std::nullopt}.toBody(),
                                  nowMs_()));
        static_cast<void>(calls_.erase(entry));
    }
    // Connect expiry: the entry survives as a relay-only route (see the
    // header comment); no wire message - the clients govern their own
    // teardown.
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void CallRegistry::relay(const std::string &peer, const std::string &wire) {
    static_cast<void>(hub_.send(peer, wire));
}

void CallRegistry::sendEnvelope(const std::string &user,
                                const linko::Envelope &envelope) {
    static_cast<void>(hub_.send(user, toWire(envelope)));
}

auto CallRegistry::isBusy(const std::string &user) const -> bool {
    return std::any_of(
        calls_.begin(), calls_.end(), [&user](const auto &entryItem) -> bool {
            const auto &call = entryItem.second;
            return (call.caller == user || call.callee == user) &&
                   call.state.kind != linko::CallStateKind::Idle &&
                   call.state.kind != linko::CallStateKind::Ended;
        });
}

auto CallRegistry::peerOf(const Call &call, const std::string &user)
    -> std::string {
    return user == call.caller ? call.callee : call.caller;
}

} // namespace server
