// Throttle implementation (Plan 3 Task 4).
#include "server/throttle.hpp"

namespace server {
namespace {

constexpr std::int64_t kWindowMs = 60 * 1000;

} // namespace

Throttle::Throttle(int perMinute, Clock nowMs)
    : perMinute_(perMinute), nowMs_(std::move(nowMs)) {}

auto Throttle::allow(const std::string &key) -> bool {
    const std::lock_guard<std::mutex> lock(mutex_);
    const std::int64_t now = nowMs_();
    auto &window = attempts_[key];
    while (!window.empty() && window.front() <= now - kWindowMs) {
        window.pop_front();
    }
    if (static_cast<int>(window.size()) >= perMinute_) {
        return false;
    }
    window.push_back(now);
    return true;
}

} // namespace server
