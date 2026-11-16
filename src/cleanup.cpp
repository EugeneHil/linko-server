// TTL cleanup for the server-side file storage (Plan 3 Task 8): deletes
// expired rows and their bytes; see server/file_store.hpp for the contract.
#include "server/file_store.hpp"

namespace server {

namespace {

constexpr std::int64_t kDayMs = 24LL * 60 * 60 * 1000;

} // namespace

void cleanupExpiredFiles(Store &store, FileStore &files, int ttlDays,
                         std::int64_t nowMs) {
    const auto cutoffMs = nowMs - (static_cast<std::int64_t>(ttlDays) * kDayMs);
    // The bytes go first: a crash in between leaves a row without a file,
    // which downloads answer with 404 - better than orphaned bytes that
    // keep counting toward the owner's quota forever.
    for (const auto &fileId : store.filesOlderThan(cutoffMs)) {
        files.remove(fileId);
        store.deleteFile(fileId);
    }
}

} // namespace server
