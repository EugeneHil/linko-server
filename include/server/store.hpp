// SQLite-backed registry of invites, users and devices (design spec 4.5
// "Accounts"). Pure persistence behind value-type results: the SQLite C API
// is used directly, no exceptions escape the runtime methods - failures
// surface as empty/false results (constructor and migrate() throw only on
// startup-path, unrecoverable SQL problems). Invite codes are stored as
// SHA-256 hex digests only; the plaintext code is handed to the caller once.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace server {

struct Invite {
    std::string code;
    std::int64_t expiresAt = 0; // epoch milliseconds
};

enum class InviteResult : std::uint8_t {
    Ok,
    NotFound,
    Expired,
    Used,
    UserMismatch,
};

struct Device {
    std::int64_t id = 0;
    std::string user;
    bool revoked = false;
};

struct RegisterResult {
    Device device;
    std::vector<std::int64_t> revokedDeviceIds;
};

class Store {
  public:
    // Produces the plaintext invite code (randomHex from LNK-17 in
    // production; tests inject a fixed one). Must not be empty when
    // createInvite is called.
    using CodeGen = std::function<std::string()>;
    // Epoch-milliseconds clock, injectable for expiry tests.
    using Clock = std::function<std::int64_t()>;

    // Opens (creating if needed) the database file, creating parent
    // directories. Throws std::runtime_error when the database cannot be
    // opened or the WAL/foreign-keys pragmas fail.
    explicit Store(const std::string &dbPath, CodeGen codeGen = {},
                   Clock nowMs = {});
    ~Store();
    Store(const Store &) = delete;
    auto operator=(const Store &) -> Store & = delete;

    // Applies pending numbered migrations inside one transaction each.
    // Idempotent: a second call with an up-to-date schema is a no-op.
    // Throws std::runtime_error when a migration fails.
    void migrate();

    // Creates a one-time invite for `user` (nullopt: any user may consume
    // it), expiring `ttlSeconds` from now. The plaintext code is returned
    // exactly once; only its SHA-256 hex digest is stored.
    [[nodiscard]] auto createInvite(std::optional<std::string> user,
                                    std::int64_t ttlSeconds) -> Invite;

    // Consumes `code` on behalf of `user`: Ok (and marks used), NotFound,
    // Expired, Used (already consumed) or UserMismatch (bound to another
    // user; the invite stays consumable by its rightful user).
    [[nodiscard]] auto consumeInvite(const std::string &code,
                                     const std::string &user) -> InviteResult;

    // Creates the user if absent and registers a new device for them,
    // revoking every previous device (one device per user, spec 4.5).
    // Returns the new device plus the ids it revoked; an empty result
    // signals an internal failure.
    [[nodiscard]] auto registerDevice(const std::string &user,
                                      const std::string &tokenHash,
                                      std::int64_t nowMs) -> RegisterResult;

    // The live device behind a token hash; nullopt when unknown or revoked.
    [[nodiscard]] auto deviceByTokenHash(const std::string &tokenHash) const
        -> std::optional<Device>;

    // Marks the user's device revoked (immediate per spec 4.5); false when
    // the device is unknown, belongs to another user or is already revoked.
    [[nodiscard]] auto revokeDevice(const std::string &user,
                                    std::int64_t deviceId, std::int64_t nowMs)
        -> bool;

    // All usernames, sorted; all devices of one user (revoked included),
    // ordered by id.
    [[nodiscard]] auto listUsers() const -> std::vector<std::string>;
    [[nodiscard]] auto listDevices(const std::string &user) const
        -> std::vector<Device>;

  private:
    // Runs a statement with no result rows; false on SQL failure.
    auto exec(const char *sql) -> bool;

    sqlite3 *db_ = nullptr;
    CodeGen codeGen_;
    Clock nowMs_;
};

} // namespace server
