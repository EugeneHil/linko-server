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
#include <utility>
#include <vector>

#include "linko/messages.hpp"

struct sqlite3;

namespace server {

// The canonical conversation key of the 1:1 pair: lexicographic
// min + '\x1f' + max, so both directions address the same row set. The
// message tables key rows by it; the messaging sink and clients treat the
// key as opaque.
[[nodiscard]] auto conversationKey(const std::string &first,
                                   const std::string &second) -> std::string;

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

// A stored file row (migration v3): the bytes live on disk under the
// FileStore's directory (path), this row tracks the rest.
struct FileRow {
    std::string id;
    std::string owner;
    std::int64_t size = 0;
    std::string sha256;
    std::int64_t createdAt = 0; // epoch milliseconds
    std::string path;
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

    // True when the user row exists (Messaging gates msg.send on it).
    [[nodiscard]] auto userExists(const std::string &user) const -> bool;

    // Stores a chat message (migration v2 tables). seq and ts are assigned
    // here - seq = MAX(seq)+1 per conversation, ts = the store's clock -
    // inside one BEGIN IMMEDIATE transaction, so concurrent sends on shared
    // conversations stay monotonic; the caller's seq/ts are ignored. A
    // duplicate message id stores nothing and returns nullopt (idempotent
    // sends, design spec 4.5 - the caller fetches the original with
    // messageById and replays it); nullopt also signals an internal SQL
    // failure.
    [[nodiscard]] auto storeMessage(linko::MessageRecord record)
        -> std::optional<linko::MessageRecord>;

    // The stored message with this id; nullopt when unknown.
    [[nodiscard]] auto messageById(const std::string &msgId) const
        -> std::optional<linko::MessageRecord>;

    // All messages of the conversation with seq > afterSeq, in seq order
    // (both directions - the conversation key covers the pair).
    [[nodiscard]] auto messagesAfter(const std::string &conversation,
                                     std::int64_t afterSeq) const
        -> std::vector<linko::MessageRecord>;

    // Conversation keys (see server::conversationKey) with a message sent
    // by or to `user`; no order guaranteed.
    [[nodiscard]] auto conversationsOf(const std::string &user) const
        -> std::vector<std::string>;

    // Moves `holder`'s receipt watermarks (delivered/read) for the
    // conversation forward; lower values than the current ones are ignored,
    // so receipts never regress. Creates the row on first touch.
    void advanceReceipts(const std::string &conversation,
                         const std::string &holder,
                         const std::string &counterpart,
                         std::int64_t deliveredUpto, std::int64_t readUpto);

    // The holder's (deliveredUpto, readUpto) pair for the conversation;
    // zeros when nothing was acked yet.
    [[nodiscard]] auto receiptsOf(const std::string &conversation,
                                  const std::string &holder,
                                  const std::string &counterpart) const
        -> std::pair<std::int64_t, std::int64_t>;

    // Records an uploaded file row (migration v3 table). The bytes live on
    // disk under the FileStore's directory; the row carries owner, size and
    // digest for the quota check, the download digest header and the TTL
    // cleanup. SQL failures are ignored like in the other void methods.
    void addFile(const FileRow &row);

    // The stored file row with this id; nullopt when unknown.
    [[nodiscard]] auto fileInfo(const std::string &fileId) const
        -> std::optional<FileRow>;

    // Ids of the files created before `cutoffMs` (created_at < cutoffMs),
    // in no particular order - the TTL cleanup's input.
    [[nodiscard]] auto filesOlderThan(std::int64_t cutoffMs) const
        -> std::vector<std::string>;

    // Removes the file row; unknown ids are tolerated.
    void deleteFile(const std::string &fileId);

    // Sum of the user's stored file sizes in bytes (0 when none) - the
    // upload quota check's input.
    [[nodiscard]] auto quotaUsed(const std::string &user) const
        -> std::uint64_t;

  private:
    // Runs a statement with no result rows; false on SQL failure.
    auto exec(const char *sql) -> bool;

    sqlite3 *db_ = nullptr;
    CodeGen codeGen_;
    Clock nowMs_;
};

} // namespace server
