// Store implementation (Plan 3 Task 2): SQLite C API behind value-type
// results; migrations are embedded, numbered, applied once.
#include "server/store.hpp"

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <utility>
#include <vector>

#include <sqlite3.h>

#include <nlohmann/json.hpp>

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

// Migration v2 (Plan 3 Task 7): chat history and receipt watermarks. The
// message id is client-generated (UUID) and globally unique - a PRIMARY KEY
// on id makes replayed sends idempotent; UNIQUE(conv, seq) backstops the
// per-conversation sequence.
constexpr const char *kMigrationV2 = R"(
CREATE TABLE messages (
  id TEXT NOT NULL,
  conv TEXT NOT NULL,
  seq INTEGER NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  text TEXT NOT NULL,
  file_json TEXT,
  ts INTEGER NOT NULL,
  PRIMARY KEY (id),
  UNIQUE (conv, seq)
);
CREATE TABLE receipts (
  conv TEXT NOT NULL,
  holder TEXT NOT NULL,
  counterpart TEXT NOT NULL,
  delivered_upto INTEGER NOT NULL DEFAULT 0,
  read_upto INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conv, holder)
);
)";

// Migration v3 (Plan 3 Task 8): server-side file storage rows. The id is
// the upload id (32 hex characters) and doubles as the disk file name under
// the FileStore's directory; the row carries the quota/digest/cleanup
// facts. The path column records where the bytes live.
constexpr const char *kMigrationV3 = R"(
CREATE TABLE files (
  id TEXT NOT NULL PRIMARY KEY,
  owner TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  path TEXT NOT NULL
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
    // Each migration runs in its own transaction; a database created by an
    // older binary walks every pending step in order.
    const auto applyStep = [this](const char *sql,
                                  std::int64_t version) -> void {
        if (!exec("BEGIN IMMEDIATE")) {
            throw std::runtime_error(
                "store: cannot begin migration transaction");
        }
        const auto markVersion =
            "INSERT INTO schema_version (version) VALUES (" +
            std::to_string(version) + ")";
        if (!exec(sql) || !exec(markVersion.c_str())) {
            static_cast<void>(exec("ROLLBACK"));
            throw std::runtime_error("store: migration step failed");
        }
        if (!exec("COMMIT")) {
            static_cast<void>(exec("ROLLBACK"));
            throw std::runtime_error("store: migration commit failed");
        }
    };
    if (current < 1) {
        applyStep(kMigrationV1, 1);
        current = 1;
    }
    if (current < 2) {
        applyStep(kMigrationV2, 2);
        current = 2;
    }
    if (current < 3) {
        applyStep(kMigrationV3, 3);
        current = 3;
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

auto Store::userExists(const std::string &user) const -> bool {
    Statement query(db_, "SELECT 1 FROM users WHERE name = ?");
    query.bindText(1, user);
    return query.step();
}

// Reads one message row in the SELECT's column order.
namespace {

// The messages INSERT parameter indexes and the readMessageRow column
// indexes shared by the message statements.
constexpr int kColId = 0;
constexpr int kColSender = 2;
constexpr int kColRecipient = 3;
constexpr int kColText = 4;
constexpr int kColFileJson = 5;
constexpr int kColSeq = 6;
constexpr int kColTs = 7;

// The messages INSERT parameter indexes.
constexpr int kBindMessageId = 1;
constexpr int kBindConv = 2;
constexpr int kBindSeq = 3;
constexpr int kBindSender = 4;
constexpr int kBindRecipient = 5;
constexpr int kBindText = 6;
constexpr int kBindFileJson = 7;
constexpr int kBindTs = 8;

// The receipts UPSERT's fifth parameter.
constexpr int kBindReadUpto = 5;

auto readMessageRow(const Statement &query) -> linko::MessageRecord {
    linko::MessageRecord record;
    record.id = query.columnText(kColId);
    record.from = query.columnText(kColSender);
    record.to = query.columnText(kColRecipient);
    record.text = query.columnText(kColText);
    const auto fileJson = query.columnText(kColFileJson);
    if (!fileJson.empty()) {
        const auto parsed = nlohmann::json::parse(fileJson, nullptr, false);
        if (!parsed.is_discarded()) {
            std::vector<linko::ValidationError> errors;
            record.file = linko::FileMeta::fromBody(parsed, errors);
        }
    }
    record.seq = query.columnInt64(kColSeq);
    record.ts = query.columnInt64(kColTs);
    return record;
}

} // namespace

auto conversationKey(const std::string &first, const std::string &second)
    -> std::string {
    constexpr char kSeparator = '\x1f';
    return first < second ? first + kSeparator + second
                          : second + kSeparator + first;
}

auto Store::storeMessage(linko::MessageRecord record)
    -> std::optional<linko::MessageRecord> {
    // Idempotent sends: the client-generated id decides. A duplicate stores
    // nothing and returns nullopt; the caller replays via messageById
    // (single connection + SQLITE_OPEN_FULLMUTEX serializes every
    // statement, so no race between the two steps).
    const auto conversation = conversationKey(record.from, record.to);
    {
        Statement existing(
            db_, "SELECT id, conv, sender, recipient, text, file_json, seq,"
                 " ts FROM messages WHERE id = ?");
        existing.bindText(1, record.id);
        if (existing.step()) {
            return std::nullopt;
        }
    }
    if (!exec("BEGIN IMMEDIATE")) {
        return std::nullopt;
    }
    std::int64_t nextSeq = 1;
    try {
        Statement maxSeq(db_, "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages"
                              " WHERE conv = ?");
        maxSeq.bindText(1, conversation);
        if (maxSeq.step()) {
            nextSeq = maxSeq.columnInt64(0);
        }
    } catch (const std::exception &) {
        static_cast<void>(exec("ROLLBACK"));
        throw;
    }

    Statement insert(db_,
                     "INSERT INTO messages (id, conv, seq, sender, recipient,"
                     " text, file_json, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    insert.bindText(kBindMessageId, record.id);
    insert.bindText(kBindConv, conversation);
    insert.bindInt64(kBindSeq, nextSeq);
    insert.bindText(kBindSender, record.from);
    insert.bindText(kBindRecipient, record.to);
    insert.bindText(kBindText, record.text);
    if (record.file.has_value()) {
        insert.bindText(kBindFileJson, record.file->toBody().dump());
    } else {
        insert.bindNull(kBindFileJson);
    }
    insert.bindInt64(kBindTs, nowMs_());
    if (!insert.run() || !exec("COMMIT")) {
        static_cast<void>(exec("ROLLBACK"));
        return std::nullopt;
    }

    record.seq = nextSeq;
    record.ts = nowMs_();
    return record;
}

auto Store::messageById(const std::string &msgId) const
    -> std::optional<linko::MessageRecord> {
    Statement query(db_, "SELECT id, conv, sender, recipient, text,"
                         " file_json, seq, ts FROM messages WHERE id = ?");
    query.bindText(1, msgId);
    if (!query.step()) {
        return std::nullopt;
    }
    return readMessageRow(query);
}

auto Store::messagesAfter(const std::string &conversation,
                          std::int64_t afterSeq) const
    -> std::vector<linko::MessageRecord> {
    Statement query(db_, "SELECT id, conv, sender, recipient, text,"
                         " file_json, seq, ts FROM messages"
                         " WHERE conv = ? AND seq > ? ORDER BY seq ASC");
    query.bindText(1, conversation);
    query.bindInt64(2, afterSeq);
    std::vector<linko::MessageRecord> messages;
    while (query.step()) {
        messages.push_back(readMessageRow(query));
    }
    return messages;
}

auto Store::conversationsOf(const std::string &user) const
    -> std::vector<std::string> {
    Statement query(db_, "SELECT DISTINCT conv FROM messages"
                         " WHERE sender = ? OR recipient = ?");
    query.bindText(1, user);
    query.bindText(2, user);
    std::vector<std::string> conversations;
    while (query.step()) {
        conversations.push_back(query.columnText(0));
    }
    return conversations;
}

void Store::advanceReceipts(const std::string &conversation,
                            const std::string &holder,
                            const std::string &counterpart,
                            std::int64_t deliveredUpto, std::int64_t readUpto) {
    // The UPSERT keeps both watermarks monotonic: MAX(current, offered)
    // ignores lower values, so a stale ack never regresses a receipt.
    Statement upsert(db_, "INSERT INTO receipts (conv, holder, counterpart,"
                          " delivered_upto, read_upto) VALUES (?, ?, ?, ?, ?)"
                          " ON CONFLICT(conv, holder) DO UPDATE SET"
                          " delivered_upto = MAX(delivered_upto,"
                          " excluded.delivered_upto),"
                          " read_upto = MAX(read_upto, excluded.read_upto)");
    upsert.bindText(1, conversation);
    upsert.bindText(2, holder);
    upsert.bindText(3, counterpart);
    upsert.bindInt64(4, deliveredUpto);
    upsert.bindInt64(kBindReadUpto, readUpto);
    static_cast<void>(upsert.run());
}

auto Store::receiptsOf(const std::string &conversation,
                       const std::string &holder,
                       const std::string &counterpart) const
    -> std::pair<std::int64_t, std::int64_t> {
    Statement query(db_, "SELECT delivered_upto, read_upto FROM receipts"
                         " WHERE conv = ? AND holder = ? AND counterpart = ?");
    query.bindText(1, conversation);
    query.bindText(2, holder);
    query.bindText(3, counterpart);
    if (!query.step()) {
        return {0, 0};
    }
    return {query.columnInt64(0), query.columnInt64(1)};
}

// The files column indexes and the readFileRow helper shared by the file
// statements.
namespace {

constexpr int kColFileId = 0;
constexpr int kColFileOwner = 1;
constexpr int kColFileSize = 2;
constexpr int kColFileSha256 = 3;
constexpr int kColFileCreatedAt = 4;
constexpr int kColFilePath = 5;
// The files INSERT parameter indexes.
constexpr int kBindFileId = 1;
constexpr int kBindFileOwner = 2;
constexpr int kBindFileSize = 3;
constexpr int kBindFileSha256 = 4;
constexpr int kBindFileCreatedAt = 5;
constexpr int kBindFilePath = 6;

auto readFileRow(const Statement &query) -> FileRow {
    FileRow row;
    row.id = query.columnText(kColFileId);
    row.owner = query.columnText(kColFileOwner);
    row.size = query.columnInt64(kColFileSize);
    row.sha256 = query.columnText(kColFileSha256);
    row.createdAt = query.columnInt64(kColFileCreatedAt);
    row.path = query.columnText(kColFilePath);
    return row;
}

} // namespace

void Store::addFile(const FileRow &row) {
    Statement insert(db_,
                     "INSERT INTO files (id, owner, size, sha256, created_at,"
                     " path) VALUES (?, ?, ?, ?, ?, ?)");
    insert.bindText(kBindFileId, row.id);
    insert.bindText(kBindFileOwner, row.owner);
    insert.bindInt64(kBindFileSize, row.size);
    insert.bindText(kBindFileSha256, row.sha256);
    insert.bindInt64(kBindFileCreatedAt, row.createdAt);
    insert.bindText(kBindFilePath, row.path);
    static_cast<void>(insert.run());
}

auto Store::fileInfo(const std::string &fileId) const
    -> std::optional<FileRow> {
    Statement query(db_, "SELECT id, owner, size, sha256, created_at, path FROM"
                         " files WHERE id = ?");
    query.bindText(1, fileId);
    if (!query.step()) {
        return std::nullopt;
    }
    return readFileRow(query);
}

auto Store::filesOlderThan(std::int64_t cutoffMs) const
    -> std::vector<std::string> {
    Statement query(db_, "SELECT id FROM files WHERE created_at < ?");
    query.bindInt64(1, cutoffMs);
    std::vector<std::string> ids;
    while (query.step()) {
        ids.push_back(query.columnText(kColFileId));
    }
    return ids;
}

void Store::deleteFile(const std::string &fileId) {
    Statement remove(db_, "DELETE FROM files WHERE id = ?");
    remove.bindText(1, fileId);
    static_cast<void>(remove.run());
}

auto Store::quotaUsed(const std::string &user) const -> std::uint64_t {
    Statement query(db_, "SELECT COALESCE(SUM(size), 0) FROM files"
                         " WHERE owner = ?");
    query.bindText(1, user);
    if (!query.step()) {
        return 0;
    }
    const auto total = query.columnInt64(0);
    return total > 0 ? static_cast<std::uint64_t>(total) : 0;
}

} // namespace server
