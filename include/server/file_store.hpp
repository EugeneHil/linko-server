// Disk-backed blob storage for the server-side file transfer (Plan 3 Task
// 8, design spec 4.5): files live under dataDir/files/<id> where <id> is a
// 32-hex-character upload id (randomHex(16)). The Store tracks the rows
// (owner, size, digest, path); this class owns the bytes on disk and the
// TTL cleanup.
#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>

#include "server/store.hpp"

namespace server {

class Writer;

class FileStore {
  public:
    // Creates dataDir/files (parent directories included). Throws
    // std::runtime_error when the directory cannot be created.
    explicit FileStore(const std::string &dataDir);

    // The disk path of the file with this id (dataDir/files/<id>).
    [[nodiscard]] auto pathOf(const std::string &fileId) const -> std::string;

    // Starts a streaming upload: opens dataDir/files/<id> for writing.
    // nullptr when the file cannot be created (the caller answers 500).
    [[nodiscard]] auto beginWrite(const std::string &fileId) const
        -> std::unique_ptr<Writer>;

    // A read-only byte stream of the stored file; the stream fails when the
    // file is missing on disk.
    [[nodiscard]] auto open(const std::string &fileId) const -> std::ifstream;

    // Deletes the file from disk; a missing file is tolerated.
    void remove(const std::string &fileId) const;

  private:
    std::string filesDir_;
};

// A streaming upload in progress (Plan 3 Task 8): the transport feeds the
// wire chunks as they arrive - no whole-file buffering - and the writer
// appends them to dataDir/files/<id> while digesting them on the fly.
// finish() closes the file and returns the lowercase SHA-256 hex (empty on
// a write failure); destroying an unfinished writer discards the partial
// file, so a cancelled upload leaves nothing behind. Non-copyable: the
// listener holds it via unique_ptr.
class Writer {
  public:
    ~Writer() noexcept;
    Writer(const Writer &) = delete;
    auto operator=(const Writer &) = delete;

    // Appends one body chunk to the partial file; false on a write failure
    // (the caller aborts the upload).
    auto feed(std::string_view chunk) -> bool;

    // The number of bytes fed so far - the response's size field.
    [[nodiscard]] auto bytesFed() const -> std::uint64_t;

    // Closes the file and returns the lowercase SHA-256 hex of everything
    // fed; empty on a write failure (the digest of an empty body is a real
    // digest, so "" is unambiguous).
    [[nodiscard]] auto finish() -> std::string;

  private:
    friend class FileStore;
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit Writer(std::string path);
};

// Deletes every expired stored file (row + bytes): rows with
// created_at < nowMs - ttlDays * 24 h. Runs at server startup and then
// every 24 hours; ttlDays and nowMs come from the config and the injected
// clock.
void cleanupExpiredFiles(Store &store, FileStore &files, int ttlDays,
                         std::int64_t nowMs);

} // namespace server
