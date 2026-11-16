// stdout capture for CLI tests (Plan 3): redirects the descriptor under
// stdout for the lifetime of the object and restores it afterwards. The
// redirection goes through dup/dup2 (POSIX) or _dup/_dup2 (MSVC) instead of
// reassigning stdout itself - MSVC's stdout macro is not an l-value, so a
// plain "stdout = fopen(...)" does not compile there.
#pragma once

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace test_util {

class CapturedStdout {
  public:
    explicit CapturedStdout(const std::string &name) {
        std::fflush(stdout);
        path_ = std::string(::testing::TempDir()) + "capture-" + name + ".txt";
        saved_ = duplicate(fileNo(stdout));
        if (saved_ == kInvalidFileNo ||
            std::freopen(path_.c_str(), "w", stdout) == nullptr) {
            if (saved_ != kInvalidFileNo) {
                closeFileNo(saved_);
            }
            // Cannot redirect: leave stdout alone; content() then simply
            // returns whatever reached the (uncaptured) stream.
            saved_ = kInvalidFileNo;
        }
    }
    ~CapturedStdout() {
        std::fflush(stdout);
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
        std::fflush(stdout);
        std::ifstream input(path_, std::ios::binary);
        return {std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>()};
    }

  private:
    using FileNo = int;
    static constexpr FileNo kInvalidFileNo = -1;

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
