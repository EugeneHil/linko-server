// Online-device hub (design spec 4.5): one socket per user (one device per
// user in v0.1), presence broadcast to every online user, user-addressed
// wire delivery. Pure in-memory state; the sessions own the sockets.
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "server/store.hpp"

namespace server {

class WsSession;

class Hub {
  public:
    using Clock = std::function<std::int64_t()>; // epoch milliseconds
    // Invoked after every successful attach (fresh socket or replacement),
    // outside the hub lock; the host wires it to Messaging::onConnect.
    using ConnectHook = std::function<void(const std::string &user)>;

    explicit Hub(Clock nowMs);

    void setConnectHook(ConnectHook hook);

    // Registers `session` as the live socket of `device.user`, closing a
    // previous socket of the same user with close code 4001 (one device
    // per user; revocation takes effect immediately, spec 4.5) and
    // broadcasting presence.changed{user, online:true} to every online
    // user (including the newcomer, so a fresh client learns who is
    // online; conversation-scoped presence is roadmap).
    void attach(const Device &device, WsSession *session);

    // Removes the session's registration; presence.changed{user,
    // online:false} goes to the users that remain.
    void detach(const Device &device, WsSession *session);

    // Sends `wire` to the online session of `user`; false when offline.
    auto send(const std::string &user, std::string_view wire) -> bool;

    [[nodiscard]] auto isOnline(const std::string &user) const -> bool;
    [[nodiscard]] auto onlineUsers() const -> std::vector<std::string>;

    // Builds and broadcasts one presence.changed envelope for `user`.
    void broadcastPresence(const std::string &user, bool online);

  private:
    Clock nowMs_;
    ConnectHook connectHook_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, WsSession *> byUser_;
    std::unordered_map<std::int64_t, std::string> userByDeviceId_;
};

} // namespace server
