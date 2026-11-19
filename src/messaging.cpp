// Messaging implementation (Plan 3 Task 7); see
// include/server/messaging.hpp for the contract.
#include "server/messaging.hpp"

#include <optional>
#include <utility>
#include <vector>

#include "linko/messages.hpp"
#include "server/wire.hpp"

namespace server {

namespace {

constexpr char kConversationSeparator = '\x1f';

// Splits a canonical conversation key into its two usernames; nullopt for
// anything that is not a two-part non-empty key.
auto conversationParts(const std::string &conversation)
    -> std::optional<std::pair<std::string, std::string>> {
    const auto separator = conversation.find(kConversationSeparator);
    if (separator == std::string::npos) {
        return std::nullopt;
    }
    const auto first = conversation.substr(0, separator);
    const auto second = conversation.substr(separator + 1);
    if (first.empty() || second.empty() ||
        second.find(kConversationSeparator) != std::string::npos) {
        return std::nullopt;
    }
    return std::make_pair(first, second);
}

} // namespace

Messaging::Messaging(Store &store, Hub &hub, Clock nowMs)
    : store_(store), hub_(hub), nowMs_(std::move(nowMs)) {}

void Messaging::onEnvelope(const std::string &fromUser,
                           const linko::Envelope &envelope,
                           std::int64_t /*deviceId*/) {
    if (envelope.type == linko::kTypeMsgSend) {
        handleSend(fromUser, envelope);
        return;
    }
    if (envelope.type == linko::kTypeMsgAckDelivered) {
        handleAck(fromUser, envelope, toWire(envelope), false);
        return;
    }
    if (envelope.type == linko::kTypeMsgAckRead) {
        handleAck(fromUser, envelope, toWire(envelope), true);
        return;
    }
    if (envelope.type == linko::kTypeMsgSync) {
        handleSync(fromUser, envelope);
    }
}

void Messaging::onSocketDrop(const std::string & /*user*/) {}

void Messaging::onConnect(const std::string &user) {
    // Per conversation: everything above the holder's delivered watermark,
    // in seq order (both directions - the client dedups by id).
    for (const auto &conversation : store_.conversationsOf(user)) {
        const auto parts = conversationParts(conversation);
        if (!parts.has_value()) {
            continue;
        }
        const auto counterpart =
            user == parts->first ? parts->second : parts->first;
        const auto [deliveredUpto, readUpto] =
            store_.receiptsOf(conversation, user, counterpart);
        static_cast<void>(readUpto);
        deliverMessages(user,
                        store_.messagesAfter(conversation, deliveredUpto));
    }
}

void Messaging::handleSend(const std::string &fromUser,
                           const linko::Envelope &envelope) {
    std::vector<linko::ValidationError> errors;
    const auto send = linko::MsgSend::fromBody(envelope.body, errors);
    if (!send.has_value()) {
        return; // malformed body: dropped (see the header comment)
    }
    if (!store_.userExists(send->to)) {
        sendEnvelope(
            fromUser,
            makeEnvelope(linko::kTypeSessionError,
                         linko::SessionError{"user_not_found", ""}.toBody(),
                         nowMs_()));
        return;
    }

    linko::MessageRecord record;
    record.id = send->id;
    record.from = fromUser;
    record.to = send->to;
    record.text = send->text;
    record.file = send->file;
    const auto stored = store_.storeMessage(std::move(record));
    if (!stored.has_value()) {
        // A duplicate id: the original row is the replay (no new seq, no
        // second delivery - the peer already received it).
        const auto original = store_.messageById(send->id);
        if (!original.has_value()) {
            return; // internal store failure: nothing to ack
        }
        sendEnvelope(fromUser, makeEnvelope(linko::kTypeMsgStored,
                                            linko::MsgStored{
                                                original->id,
                                                original->seq,
                                                original->ts,
                                            }
                                                .toBody(),
                                            nowMs_()));
        return;
    }
    sendEnvelope(
        fromUser,
        makeEnvelope(
            linko::kTypeMsgStored,
            linko::MsgStored{stored->id, stored->seq, stored->ts}.toBody(),
            nowMs_()));
    // Online peer only; offline delivery happens on connect (receipts).
    if (hub_.isOnline(stored->to)) {
        deliverMessages(stored->to, {
                                        *stored,
                                    });
    }
}

void Messaging::handleAck(const std::string &fromUser,
                          const linko::Envelope &envelope,
                          const std::string &wire, bool read) {
    std::vector<linko::ValidationError> errors;
    const auto ack = linko::MsgAck::fromBody(envelope.body, errors);
    if (!ack.has_value()) {
        return;
    }
    // The body names the canonical conversation key; the sender must be one
    // of its two members (they are the holder), and the receipt is stored
    // under the same key space the message tables use.
    const auto parts = conversationParts(ack->conversation);
    if (!parts.has_value() ||
        (fromUser != parts->first && fromUser != parts->second)) {
        return;
    }
    const auto peer = fromUser == parts->first ? parts->second : parts->first;
    const auto conversation = conversationKey(parts->first, parts->second);
    if (read) {
        store_.advanceReceipts(conversation, fromUser, peer, 0, ack->uptoSeq);
    } else {
        store_.advanceReceipts(conversation, fromUser, peer, ack->uptoSeq, 0);
    }
    // The receipt belongs to the peer's messages: forward unchanged.
    static_cast<void>(hub_.send(peer, wire));
}

void Messaging::handleSync(const std::string &fromUser,
                           const linko::Envelope &envelope) {
    std::vector<linko::ValidationError> errors;
    const auto sync = linko::MsgSync::fromBody(envelope.body, errors);
    if (!sync.has_value()) {
        return;
    }
    // Only the user's own conversation key replays: anything else names a
    // conversation they are not part of.
    const auto parts = conversationParts(sync->conversation);
    if (!parts.has_value() ||
        (fromUser != parts->first && fromUser != parts->second)) {
        return;
    }
    const auto conversation = conversationKey(parts->first, parts->second);
    deliverMessages(fromUser,
                    store_.messagesAfter(conversation, sync->afterSeq));
}

void Messaging::deliverMessages(
    const std::string &toUser,
    const std::vector<linko::MessageRecord> &messages) {
    for (const auto &message : messages) {
        sendEnvelope(toUser, makeEnvelope(linko::kTypeMsgDeliver,
                                          linko::MsgDeliver{message}.toBody(),
                                          nowMs_()));
    }
}

void Messaging::sendEnvelope(const std::string &user,
                             const linko::Envelope &envelope) {
    static_cast<void>(hub_.send(user, toWire(envelope)));
}

} // namespace server
