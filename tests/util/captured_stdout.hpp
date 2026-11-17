// stdout capture for CLI tests (Plan 3): redirects the descriptor under
// stdout for the lifetime of the object and restores it afterwards. The
// redirection swaps fd 1 itself (open the capture file, dup2 it onto
// stdout's descriptor, close the temporary one) instead of reopening the
// stream: MSVC's stdout is not an l-value, so a plain "stdout = fopen(...)"
// does not compile, and freopen_s - which replaces the stdout FILE object -
// silently lost every write the CLI made through it on the MSVC runners
// (CLI exit 0, empty capture file, nothing on the console; LNK-25 CI). With
// fd-level redirection the stdout FILE object and its buffer stay intact;
// only the descriptor they write to changes.
#pragma once

#include <gtest/gtest.h>

#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <string>

#if defined(_WIN32)
#include <io.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#endif

namespace test_util {

class CapturedStdout {
  public:
    explicit CapturedStdout(const std::string &name) {
        std::fflush(nullptr);
        path_ = std::string(::testing::TempDir()) + "capture-" + name + ".txt";
        saved_ = duplicate(fileNo(stdout));
        if (saved_ == kInvalidFileNo || !redirectStdoutTo(path_)) {
            if (saved_ != kInvalidFileNo) {
                closeFileNo(saved_);
            }
            // Cannot redirect: leave stdout alone; content() then simply
            // returns whatever reached the (uncaptured) stream.
            saved_ = kInvalidFileNo;
        }
    }
    ~CapturedStdout() {
        std::fflush(nullptr);
        if (saved_ != kInvalidFileNo) {
            moveDuplicate(saved_, fileNo(stdout));
            closeFileNo(saved_);
        }
    }
    CapturedStdout(const CapturedStdout &) = delete;
    auto operator=(const CapturedStdout &) -> CapturedStdout & = delete;

    [[nodiscard]] auto content() const -> std::string {
        // stdout is fully buffered while redirected to a file: flush so
        // reads inside the capture scope see what the code has printed.
        std::fflush(nullptr);
        std::ifstream input(path_, std::ios::binary);
        return {std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>()};
    }

  private:
    using FileNo = int;
    static constexpr FileNo kInvalidFileNo = -1;
    // 0644: the capture file holds nothing sensitive, but stays private.
    static constexpr int kCaptureFilePermissions = 0644;

    static auto redirectStdoutTo(const std::string &path) -> bool {
#if defined(_WIN32)
        // _open is deprecated (C4996, warnings are errors); _sopen_s is the
        // sanctioned spelling and reports failures by setting the
        // out-descriptor to -1.
        int fileFd = kInvalidFileNo;
        static_cast<void>(::_sopen_s(&fileFd, path.c_str(),
                                     _O_WRONLY | _O_CREAT | _O_TRUNC | _O_TEXT,
                                     _SH_DENYNO, _S_IREAD | _S_IWRITE));
        const FileNo stdoutFd = 1;
#else
        const int fileFd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                                  kCaptureFilePermissions);
        const FileNo stdoutFd = STDOUT_FILENO;
#endif
        if (fileFd == kInvalidFileNo) {
            return false;
        }
        if (moveDuplicateChecked(fileFd, stdoutFd) != 0) {
            closeFileNo(fileFd);
            return false;
        }
        closeFileNo(fileFd);
        return true;
    }

    static auto moveDuplicateChecked(FileNo from, FileNo to) -> int {
#if defined(_WIN32)
        return ::_dup2(from, to);
#else
        return ::dup2(from, to);
#endif
    }

#if defined(_WIN32)
    static auto fileNo(FILE *file) -> FileNo { return _fileno(file); }
    static auto duplicate(FileNo fd) -> FileNo { return _dup(fd); }
    static void moveDuplicate(FileNo from, FileNo to) {
        static_cast<void>(_dup2(from, to));
    }
    static void closeFileNo(FileNo fd) { static_cast<void>(_close(fd)); }
#else
    static auto fileNo(FILE *file) -> FileNo { return ::fileno(file); }
    static auto duplicate(FileNo fd) -> FileNo { return ::dup(fd); }
    static void moveDuplicate(FileNo from, FileNo to) {
        static_cast<void>(::dup2(from, to));
    }
    static void closeFileNo(FileNo fd) { static_cast<void>(::close(fd)); }
#endif

    FileNo saved_ = kInvalidFileNo;
    std::string path_;
};

} // namespace test_util
