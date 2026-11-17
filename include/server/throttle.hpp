// Sliding-window rate limiter keyed by an opaque key (the client address
// for register attempts, the device id for envelope budgets). Injectable
// clock: tests move time forward explicitly, no sleeps.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace server {

class Throttle {
  public:
    using Clock = std::function<std::int64_t()>; // epoch milliseconds

    // `perMinute` attempts per 60-second window per key.
    Throttle(int perMinute, Clock nowMs);

    // True (and records the attempt) when `key` is under its budget in the
    // current window; false once `perMinute` attempts are already recorded.
    auto allow(const std::string &key) -> bool;

  private:
    int perMinute_;
    Clock nowMs_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::deque<std::int64_t>> attempts_;
};

} // namespace server
