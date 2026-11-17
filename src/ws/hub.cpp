// Hub implementation (Plan 3 Task 5).
#include "server/hub.hpp"

#include <utility>

#include "linko/messages.hpp"
#include "server/wire.hpp"
#include "server/ws_session.hpp"

namespace server {

namespace linko_ = linko; // alias for readability below

Hub::Hub(Clock nowMs) : nowMs_(std::move(nowMs)) {}

void Hub::setConnectHook(ConnectHook hook) { connectHook_ = std::move(hook); }

void Hub::attach(const Device &device, WsSession *session) {
    WsSession *previous = nullptr;
    {
        const std::scoped_lock lock(mutex_);
        const auto existing = byUser_.find(device.user);
        if (existing != byUser_.end()) {
            previous = existing->second;
        }
        byUser_[device.user] = session;
        userByDeviceId_[device.id] = device.user;
    }
    if (previous != nullptr && previous != session) {
        // Another socket of the same user: close it with 4001 so its drop
        // path removes only itself (identity-checked detach).
        previous->close(kWsCloseAnotherSocket);
    }
    broadcastPresence(device.user, true);
    // The connect hook runs last, outside the lock: the backlog push it
    // performs queries the store and sends through this hub again.
    if (connectHook_) {
        connectHook_(device.user);
    }
}

void Hub::detach(const Device &device, WsSession *session) {
    bool removed = false;
    {
        const std::scoped_lock lock(mutex_);
        const auto existing = byUser_.find(device.user);
        if (existing != byUser_.end() && existing->second == session) {
            byUser_.erase(existing);
            removed = true;
        }
        userByDeviceId_.erase(device.id);
    }
    if (removed) {
        broadcastPresence(device.user, false);
    }
}

auto Hub::send(const std::string &user, std::string_view wire) -> bool {
    WsSession *session = nullptr;
    {
        const std::scoped_lock lock(mutex_);
        const auto existing = byUser_.find(user);
        if (existing == byUser_.end()) {
            return false;
        }
        session = existing->second;
    }
    return session->send(wire);
}

auto Hub::isOnline(const std::string &user) const -> bool {
    const std::scoped_lock lock(mutex_);
    return byUser_.find(user) != byUser_.end();
}

auto Hub::onlineUsers() const -> std::vector<std::string> {
    const std::scoped_lock lock(mutex_);
    std::vector<std::string> users;
    users.reserve(byUser_.size());
    for (const auto &[user, session] : byUser_) {
        users.push_back(user);
    }
    return users;
}

void Hub::broadcastPresence(const std::string &user, bool online) {
    const auto envelope =
        makeEnvelope(linko_::kTypePresenceChanged,
                     linko_::PresenceChanged{user, online}.toBody(), nowMs_());
    const auto wire = toWire(envelope);
    std::vector<WsSession *> sessions;
    {
        const std::scoped_lock lock(mutex_);
        sessions.reserve(byUser_.size());
        for (auto &[onlineUser, session] : byUser_) {
            sessions.push_back(session);
        }
    }
    for (WsSession *session : sessions) {
        static_cast<void>(session->send(wire));
    }
}

} // namespace server
