// Messaging (design spec 4.5, Plan 3 Task 7): chat persistence and delivery
// over the Store's message tables and the Hub's live sockets. One sequence
// per conversation (both directions share it), client-generated message ids
// make sends idempotent, receipts are monotonic watermarks, and reconnects
// push everything the user's delivered watermark does not yet cover.
//
// Wire rules:
// - msg.send with an unknown recipient is answered with
//   session.error{code:"user_not_found"} and stores nothing; otherwise the
//   sender gets msg.stored{id, seq, ts} (a duplicate id replays the original
//   seq/ts and stores nothing) and the online peer gets
//   msg.deliver{message};
// - msg.ack-delivered / msg.ack-read advance the sender's watermarks (as the
//   holder) for the conversation named in the body - the canonical
//   conversation key (min\x1fmax); the ack is forwarded unchanged to the
//   key's other member, so the sender of the original messages learns the
//   receipts. Bodies that name anything but the sender's own two-part
//   conversation key are dropped whole;
// - msg.sync{conversation, afterSeq} replays one msg.deliver per stored
//   message after afterSeq, in seq order; the conversation is the canonical
//   key, and a key the sender is not part of replays nothing;
// - onConnect pushes, per conversation, every message above the user's
//   delivered watermark, in seq order (at-least-once: an unacked delivery is
//   redelivered on reconnect, clients dedup by id).
//
// Malformed typed bodies are dropped silently: the session already gates
// envelope shape, and only a hostile client can produce one (same rule as
// the call registry). Thread model: the sink is called from per-connection
// strands but holds no mutable state of its own - the store serializes SQL
// (FULLMUTEX + transactions) and hub.send is leaf-locked.
#pragma once

#include <functional>
#include <string>

#include "linko/envelope.hpp"
#include "server/hub.hpp"
#include "server/store.hpp"
#include "server/ws_session.hpp"

namespace server {

// server::conversationKey (store.hpp) keys the conversation tables; the
// messaging sink treats the key as opaque.

class Messaging final : public ProtocolSink {
  public:
    using Clock = std::function<std::int64_t()>; // epoch milliseconds

    Messaging(Store &store, Hub &hub, Clock nowMs);
    ~Messaging() override = default;
    Messaging(const Messaging &) = delete;
    auto operator=(const Messaging &) -> Messaging & = delete;

    void onEnvelope(const std::string &fromUser,
                    const linko::Envelope &envelope,
                    std::int64_t deviceId) override;
    // Nothing to clean up: messages are store-backed, the backlog is keyed
    // on receipts, not on live sessions.
    void onSocketDrop(const std::string &user) override;

    // Pushes the undelivered backlog for `user`; wired to the hub's connect
    // hook by the host (cli.cpp, test fixtures).
    void onConnect(const std::string &user);

  private:
    void handleSend(const std::string &fromUser,
                    const linko::Envelope &envelope);
    void handleAck(const std::string &fromUser, const linko::Envelope &envelope,
                   const std::string &wire, bool read);
    void handleSync(const std::string &fromUser,
                    const linko::Envelope &envelope);
    void deliverMessages(const std::string &toUser,
                         const std::vector<linko::MessageRecord> &messages);
    void sendEnvelope(const std::string &user, const linko::Envelope &envelope);

    Store &store_;
    Hub &hub_;
    Clock nowMs_;
};

} // namespace server
