// FileStore implementation (Plan 3 Task 8): the bytes of every uploaded
// file live under dataDir/files/<id>; ids are validated by the callers, so
// this layer treats them as plain path components. The streaming upload
// digest is backed by OpenSSL's EVP interface - already a dependency
// (ADR-0003) - because the vendored core digest has no incremental form;
// finishHex renders the same lowercase hex linko::sha256Hex would produce
// for the concatenation, so the digest stays wire-compatible.
#include "server/file_store.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <utility>

#include <openssl/evp.h>

#include "linko/sha256.hpp"

namespace server {

namespace {

// Incremental SHA-256 for the streaming upload digest: chunks are digested
// as they arrive, nothing beyond one wire chunk is ever buffered.
class Sha256Stream {
  public:
    Sha256Stream() : ctx_(EVP_MD_CTX_new()) {
        if (ctx_ == nullptr ||
            EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("file_store: cannot start the digest");
        }
    }
    Sha256Stream(const Sha256Stream &) = delete;
    auto operator=(const Sha256Stream &) = delete;

    void update(const char *data, std::size_t size) {
        if (EVP_DigestUpdate(ctx_.get(), data, size) != 1) {
            throw std::runtime_error("file_store: digest update failed");
        }
    }

    // The lowercase hex of everything fed so far; "" on a digest failure
    // (a real digest is never empty, so "" is unambiguous).
    [[nodiscard]] auto finishHex() -> std::string {
        linko::Sha256Digest digest{};
        unsigned int size = 0;
        if (EVP_DigestFinal_ex(ctx_.get(), digest.data(), &size) != 1 ||
            size != linko::kSha256DigestBytes) {
            return "";
        }
        return linko::toHex(digest);
    }

  private:
    struct CtxDeleter {
        void operator()(EVP_MD_CTX *context) const noexcept {
            EVP_MD_CTX_free(context);
        }
    };
    std::unique_ptr<EVP_MD_CTX, CtxDeleter> ctx_;
};

} // namespace

// The streaming writer state: the partial file, the running digest and the
// fed byte count. The digest and the file receive one chunk at a time.
struct Writer::Impl {
    explicit Impl(std::string filePath)
        : path(std::move(filePath)),
          file(path, std::ios::binary | std::ios::trunc) {}

    std::string path;
    std::ofstream file;
    Sha256Stream digest;
    std::uint64_t fedBytes = 0;
    bool finished = false;
};

Writer::Writer(std::string path)
    : impl_(std::make_unique<Impl>(std::move(path))) {}

// The ofstream member's destructor and the error_code filesystem call
// cannot throw in practice; the check cannot see that through unique_ptr.
// NOLINTNEXTLINE(bugprone-exception-escape)
Writer::~Writer() noexcept {
    if (impl_ == nullptr) {
        return;
    }
    if (!impl_->finished) {
        impl_->file.close();
        std::error_code ignored;
        std::filesystem::remove(impl_->path, ignored);
    }
}

auto Writer::feed(std::string_view chunk) -> bool {
    impl_->file.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    if (impl_->file.fail()) {
        return false;
    }
    try {
        impl_->digest.update(chunk.data(), chunk.size());
    } catch (const std::exception &) {
        return false;
    }
    impl_->fedBytes += chunk.size();
    return true;
}

auto Writer::bytesFed() const -> std::uint64_t { return impl_->fedBytes; }

auto Writer::finish() -> std::string {
    impl_->file.close();
    if (impl_->file.fail()) {
        return "";
    }
    std::string digestHex;
    try {
        digestHex = impl_->digest.finishHex();
    } catch (const std::exception &) {
        return "";
    }
    impl_->finished = true;
    return digestHex;
}

FileStore::FileStore(const std::string &dataDir)
    : filesDir_((std::filesystem::path(dataDir) / "files").string()) {
    std::error_code error;
    std::filesystem::create_directories(filesDir_, error);
    if (error) {
        throw std::runtime_error("file_store: cannot create " + filesDir_ +
                                 ": " + error.message());
    }
}

auto FileStore::pathOf(const std::string &fileId) const -> std::string {
    return (std::filesystem::path(filesDir_) / fileId).string();
}

auto FileStore::beginWrite(const std::string &fileId) const
    -> std::unique_ptr<Writer> {
    std::unique_ptr<Writer> writer(new Writer(pathOf(fileId)));
    if (!writer->impl_->file.is_open()) {
        return nullptr;
    }
    return writer;
}

auto FileStore::open(const std::string &fileId) const -> std::ifstream {
    return std::ifstream(pathOf(fileId), std::ios::binary);
}

void FileStore::remove(const std::string &fileId) const {
    std::error_code ignored;
    std::filesystem::remove(pathOf(fileId), ignored);
}

} // namespace server
