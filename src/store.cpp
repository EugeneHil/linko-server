// Store implementation (Plan 3 Task 2): SQLite C API behind value-type
// results; migrations are embedded, numbered, applied once.
#include "server/store.hpp"

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <utility>
#include <vector>

#include <sqlite3.h>

#include "linko/sha256.hpp"

namespace server {
namespace {

// A prepared statement with typed bind/read helpers. Prepare failures throw:
// they are compile-time SQL bugs, caught by the test suite immediately.
class Statement {
  public:
    Statement(sqlite3 *database, const char *sql) {
        const int resultCode =
            sqlite3_prepare_v2(database, sql, -1, &stmt_, nullptr);
        if (resultCode != SQLITE_OK) {
            throw std::runtime_error(std::string("store: prepare failed: ") +
                                     sqlite3_errmsg(database));
        }
    }
    ~Statement() { sqlite3_finalize(stmt_); }
    Statement(const Statement &) = delete;
    auto operator=(const Statement &) -> Statement & = delete;

    void bindText(int index, const std::string &value) {
        sqlite3_bind_text(stmt_, index, value.c_str(),
                          static_cast<int>(value.size()), SQLITE_TRANSIENT);
    }
    void bindInt64(int index, std::int64_t value) {
        sqlite3_bind_int64(stmt_, index, value);
    }
    void bindNull(int index) { sqlite3_bind_null(stmt_, index); }

    // True when a row is available.
    [[nodiscard]] auto step() -> bool {
        return sqlite3_step(stmt_) == SQLITE_ROW;
    }
    // True when the statement ran to completion (INSERT/UPDATE/DELETE).
    [[nodiscard]] auto run() -> bool {
        return sqlite3_step(stmt_) == SQLITE_DONE;
    }

    [[nodiscard]] auto columnInt64(int index) const -> std::int64_t {
        return sqlite3_column_int64(stmt_, index);
    }
    [[nodiscard]] auto columnText(int index) const -> std::string {
        const auto *text = sqlite3_column_text(stmt_, index);
        return text == nullptr
                   ? std::string()
                   : std::string(reinterpret_cast<const char *>(text));
    }

  private:
    sqlite3_stmt *stmt_ = nullptr;
};

constexpr std::int64_t kSecondMs = 1000;

auto sha256HexOfString(const std::string &value) -> std::string {
    return linko::sha256Hex(
        std::vector<std::uint8_t>(value.begin(), value.end()));
}

auto systemNowMs() -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr const char *kMigrationV1 = R"(
CREATE TABLE invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL UNIQUE,
  user TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER,
  created_at INTEGER NOT NULL
);
)";

} // namespace

Store::Store(const std::string &dbPath, CodeGen codeGen, Clock nowMs)
    : codeGen_(std::move(codeGen)) {
    nowMs_ = nowMs != nullptr ? std::move(nowMs) : Clock{&systemNowMs};
    const auto parent = std::filesystem::path(dbPath).parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }
    const int resultCode = sqlite3_open_v2(
        dbPath.c_str(), &db_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr);
    if (resultCode != SQLITE_OK) {
        const std::string message =
            db_ != nullptr ? sqlite3_errmsg(db_) : "unknown error";
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        throw std::runtime_error("store: cannot open " + dbPath + ": " +
                                 message);
    }
    if (!exec("PRAGMA journal_mode = WAL") ||
        !exec("PRAGMA foreign_keys = ON")) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("store: pragmas failed for " + dbPath);
    }
}

Store::~Store() {
    if (db_ != nullptr) {
        sqlite3_close(db_);
    }
}

auto Store::exec(const char *sql) -> bool {
    char *error = nullptr;
    const int resultCode = sqlite3_exec(db_, sql, nullptr, nullptr, &error);
    if (error != nullptr) {
        sqlite3_free(error);
    }
    return resultCode == SQLITE_OK;
}

void Store::migrate() {
    if (!exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT "
              "NULL)")) {
        throw std::runtime_error("store: cannot create schema_version");
    }
    std::int64_t current = 0;
    {
        Statement query(db_, "SELECT MAX(version) FROM schema_version");
        if (query.step()) {
            current = query.columnInt64(0);
        }
    }
    if (current >= 1) {
        return;
    }
    if (!exec("BEGIN IMMEDIATE")) {
        throw std::runtime_error("store: cannot begin migration transaction");
    }
    if (!exec(kMigrationV1) ||
        !exec("INSERT INTO schema_version (version) VALUES (1)")) {
        static_cast<void>(exec("ROLLBACK"));
        throw std::runtime_error("store: migration v1 failed");
    }
    if (!exec("COMMIT")) {
        static_cast<void>(exec("ROLLBACK"));
        throw std::runtime_error("store: migration commit failed");
    }
}

auto Store::createInvite(std::optional<std::string> user,
                         std::int64_t ttlSeconds) -> Invite {
    if (!codeGen_) {
        throw std::logic_error("store: no code generator injected");
    }
    const auto code = codeGen_();
    const std::int64_t createdAt = nowMs_();
    const std::int64_t expiresAt = createdAt + (ttlSeconds * kSecondMs);
    Statement insert(db_,
                     "INSERT INTO invites (code_hash, user, expires_at, used,"
                     " created_at) VALUES (?, ?, ?, 0, ?)");
    insert.bindText(1, sha256HexOfString(code));
    if (user.has_value()) {
        insert.bindText(2, *user);
    } else {
        insert.bindNull(2);
    }
    insert.bindInt64(3, expiresAt);
    insert.bindInt64(4, createdAt);
    if (!insert.run()) {
        return {};
    }
    return Invite{code, expiresAt};
}

// The (code, user) order is fixed by the interface in the plan.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto Store::consumeInvite(const std::string &code, const std::string &user)
    -> InviteResult {
    Statement lookup(db_, "SELECT id, user, expires_at, used FROM invites"
                          " WHERE code_hash = ?");
    lookup.bindText(1, sha256HexOfString(code));
    if (!lookup.step()) {
        return InviteResult::NotFound;
    }
    const auto inviteId = lookup.columnInt64(0);
    const auto boundUser = lookup.columnText(1);
    const auto expiresAt = lookup.columnInt64(2);
    const auto used = lookup.columnInt64(3) != 0;
    if (used) {
        return InviteResult::Used;
    }
    if (nowMs_() >= expiresAt) {
        return InviteResult::Expired;
    }
    if (!boundUser.empty() && boundUser != user) {
        return InviteResult::UserMismatch;
    }
    Statement mark(db_, "UPDATE invites SET used = 1 WHERE id = ?");
    mark.bindInt64(1, inviteId);
    if (!mark.run()) {
        return InviteResult::NotFound;
    }
    return InviteResult::Ok;
}

auto Store::registerDevice(const std::string &user,
                           const std::string &tokenHash, std::int64_t nowMs)
    -> RegisterResult {
    if (!exec("BEGIN IMMEDIATE")) {
        return {};
    }
    std::int64_t userId = 0;
    try {
        Statement findUser(db_, "SELECT id FROM users WHERE name = ?");
        findUser.bindText(1, user);
        if (findUser.step()) {
            userId = findUser.columnInt64(0);
        } else {
            Statement insertUser(
                db_, "INSERT INTO users (name, created_at) VALUES (?, ?)");
            insertUser.bindText(1, user);
            insertUser.bindInt64(2, nowMs);
            if (!insertUser.run()) {
                static_cast<void>(exec("ROLLBACK"));
                return {};
            }
            userId = sqlite3_last_insert_rowid(db_);
        }
    } catch (const std::exception &) {
        static_cast<void>(exec("ROLLBACK"));
        throw;
    }

    std::vector<std::int64_t> revoked;
    try {
        Statement previous(db_, "SELECT id FROM devices WHERE user_id = ?"
                                " AND revoked = 0");
        previous.bindInt64(1, userId);
        while (previous.step()) {
            revoked.push_back(previous.columnInt64(0));
        }
        if (!revoked.empty()) {
            Statement revokePrevious(
                db_, "UPDATE devices SET revoked = 1, revoked_at = ?"
                     " WHERE user_id = ? AND revoked = 0");
            revokePrevious.bindInt64(1, nowMs);
            revokePrevious.bindInt64(2, userId);
            if (!revokePrevious.run()) {
                static_cast<void>(exec("ROLLBACK"));
                return {};
            }
        }
        Statement insertDevice(
            db_, "INSERT INTO devices (user_id, token_hash, created_at)"
                 " VALUES (?, ?, ?)");
        insertDevice.bindInt64(1, userId);
        insertDevice.bindText(2, tokenHash);
        insertDevice.bindInt64(3, nowMs);
        if (!insertDevice.run()) {
            static_cast<void>(exec("ROLLBACK"));
            return {};
        }
    } catch (const std::exception &) {
        static_cast<void>(exec("ROLLBACK"));
        throw;
    }
    const auto deviceId = sqlite3_last_insert_rowid(db_);
    if (!exec("COMMIT")) {
        static_cast<void>(exec("ROLLBACK"));
        return {};
    }
    return RegisterResult{Device{deviceId, user, false}, revoked};
}

auto Store::deviceByTokenHash(const std::string &tokenHash) const
    -> std::optional<Device> {
    Statement query(
        db_, "SELECT d.id, u.name FROM devices d JOIN users u"
             " ON d.user_id = u.id WHERE d.token_hash = ? AND d.revoked = 0");
    query.bindText(1, tokenHash);
    if (!query.step()) {
        return std::nullopt;
    }
    return Device{query.columnInt64(0), query.columnText(1), false};
}

auto Store::revokeDevice(const std::string &user, std::int64_t deviceId,
                         std::int64_t nowMs) -> bool {
    Statement revoke(
        db_, "UPDATE devices SET revoked = 1, revoked_at = ? WHERE id = ?"
             " AND revoked = 0 AND user_id = (SELECT id FROM users"
             " WHERE name = ?)");
    revoke.bindInt64(1, nowMs);
    revoke.bindInt64(2, deviceId);
    revoke.bindText(3, user);
    if (!revoke.run()) {
        return false;
    }
    return sqlite3_changes(db_) == 1;
}

auto Store::listUsers() const -> std::vector<std::string> {
    Statement query(db_, "SELECT name FROM users ORDER BY name");
    std::vector<std::string> users;
    while (query.step()) {
        users.push_back(query.columnText(0));
    }
    return users;
}

auto Store::listDevices(const std::string &user) const -> std::vector<Device> {
    Statement query(db_, "SELECT d.id, u.name, d.revoked FROM devices d"
                         " JOIN users u ON d.user_id = u.id WHERE u.name = ?"
                         " ORDER BY d.id");
    query.bindText(1, user);
    std::vector<Device> devices;
    while (query.step()) {
        devices.push_back(Device{
            query.columnInt64(0),
            query.columnText(1),
            query.columnInt64(2) != 0,
        });
    }
    return devices;
}

} // namespace server
