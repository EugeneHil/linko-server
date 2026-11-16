// Store: migrations, invites, devices, receipt-free user/device registry
// (Plan 3 Task 2). Every test uses GoogleTest's TempDir for its database so
// runs never collide, and a fixed, injectable clock/code generator.
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "server/store.hpp"

namespace {

// The fixed epoch every timestamp in this suite derives from.
constexpr std::int64_t kBaseMs = 1790000000000;
constexpr std::int64_t kSecondMs = 1000;
constexpr std::int64_t kHourTtlSeconds = 3600;
constexpr std::int64_t kMinuteTtlSeconds = 60;
constexpr std::int64_t kPastExpiryMs = (kMinuteTtlSeconds + 1) * kSecondMs;
constexpr std::int64_t kSecondRegisterMs = kBaseMs + 1;
constexpr std::int64_t kRevokeAtMs = kBaseMs + 5;
constexpr std::int64_t kRevokeAgainMs = kBaseMs + 6;
// The lowercase SHA-256 hex digest of "FIXEDCODE", computed independently.
constexpr const char *kFixedCodeHash =
    "909cb27040334988427d266c6f28500b069bb0d58a8101dd4f95567c828cff9c";

// Removes a temp database (plus WAL/SHM sidecars) before a test opens it.
void removeDb(const std::string &path) {
    for (const auto *const suffix : {"", "-wal", "-shm"}) {
        std::error_code ignored;
        std::filesystem::remove(path + suffix, ignored);
    }
}

// Fixed clock: the test moves the time forward explicitly; no sleeps.
class FakeClock {
  public:
    explicit FakeClock(std::int64_t startMs) : nowMs_(startMs) {}
    [[nodiscard]] auto tick() const -> std::int64_t { return nowMs_; }
    void advance(std::int64_t deltaMs) { nowMs_ += deltaMs; }

  private:
    std::int64_t nowMs_;
};

struct Fixture {
    explicit Fixture(const std::string &name)
        : dbPath(std::string(::testing::TempDir()) + "linko-store-" + name +
                 ".db"),
          clock(kBaseMs) {
        removeDb(dbPath);
    }

    auto makeStore() -> server::Store {
        return server::Store(
            dbPath, []() -> std::string { return "FIXEDCODE"; },
            [this]() -> std::int64_t { return clock.tick(); });
    }

    std::string dbPath;
    FakeClock clock;
};

auto readFileBytes(const std::string &path) -> std::string {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

} // namespace

TEST(Store, MigrateCreatesSchemaAndIsIdempotent) {
    Fixture fixture("migrate");
    auto store = fixture.makeStore();
    store.migrate();
    // A second run must be a no-op, not a schema error.
    store.migrate();
    // The schema works: an invite roundtrips after both migrations.
    const auto invite = store.createInvite(std::nullopt, kHourTtlSeconds);
    EXPECT_EQ(invite.code, "FIXEDCODE");
}

TEST(Store, InviteRoundtrip) {
    Fixture fixture("invite-ok");
    auto store = fixture.makeStore();
    store.migrate();
    const auto invite = store.createInvite(std::nullopt, kHourTtlSeconds);
    EXPECT_EQ(invite.code, "FIXEDCODE");
    EXPECT_EQ(invite.expiresAt, kBaseMs + (kHourTtlSeconds * kSecondMs));
    fixture.clock.advance(kSecondMs);
    EXPECT_EQ(store.consumeInvite(invite.code, "anna"),
              server::InviteResult::Ok);
}

TEST(Store, InviteExpired) {
    Fixture fixture("invite-expired");
    auto store = fixture.makeStore();
    store.migrate();
    const auto invite = store.createInvite(std::nullopt, kMinuteTtlSeconds);
    fixture.clock.advance(kPastExpiryMs);
    EXPECT_EQ(store.consumeInvite(invite.code, "anna"),
              server::InviteResult::Expired);
}

TEST(Store, InviteSingleUse) {
    Fixture fixture("invite-used");
    auto store = fixture.makeStore();
    store.migrate();
    const auto invite = store.createInvite(std::nullopt, kHourTtlSeconds);
    EXPECT_EQ(store.consumeInvite(invite.code, "anna"),
              server::InviteResult::Ok);
    EXPECT_EQ(store.consumeInvite(invite.code, "anna"),
              server::InviteResult::Used);
}

TEST(Store, InviteUserMismatch) {
    Fixture fixture("invite-mismatch");
    auto store = fixture.makeStore();
    store.migrate();
    const auto invite =
        store.createInvite(std::string("anna"), kHourTtlSeconds);
    EXPECT_EQ(store.consumeInvite(invite.code, "bob"),
              server::InviteResult::UserMismatch);
    // A mismatch does not consume the invite: the rightful user still
    // registers.
    EXPECT_EQ(store.consumeInvite(invite.code, "anna"),
              server::InviteResult::Ok);
}

TEST(Store, RegisterCreatesUserAndDevice) {
    Fixture fixture("register-first");
    auto store = fixture.makeStore();
    store.migrate();
    const auto result = store.registerDevice("eugene", "hash-1", kBaseMs);
    EXPECT_GT(result.device.id, 0);
    EXPECT_EQ(result.device.user, "eugene");
    EXPECT_TRUE(result.revokedDeviceIds.empty());
    const auto device = store.deviceByTokenHash("hash-1");
    if (!device.has_value()) {
        FAIL() << "device must resolve right after registration";
    }
    EXPECT_EQ(device->id, result.device.id);
    EXPECT_EQ(device->user, "eugene");
}

TEST(Store, RegisterRevokesPreviousDevice) {
    Fixture fixture("register-revoke");
    auto store = fixture.makeStore();
    store.migrate();
    const auto first = store.registerDevice("eugene", "hash-1", kBaseMs);
    const auto second =
        store.registerDevice("eugene", "hash-2", kSecondRegisterMs);
    ASSERT_EQ(second.revokedDeviceIds.size(), 1U);
    EXPECT_EQ(second.revokedDeviceIds[0], first.device.id);
    EXPECT_FALSE(store.deviceByTokenHash("hash-1").has_value());
    EXPECT_TRUE(store.deviceByTokenHash("hash-2").has_value());
}

TEST(Store, DeviceByTokenHashRevokedAbsent) {
    Fixture fixture("token-revoked");
    auto store = fixture.makeStore();
    store.migrate();
    static_cast<void>(store.registerDevice("eugene", "hash-1", kBaseMs));
    const auto device = store.deviceByTokenHash("hash-1");
    if (!device.has_value()) {
        FAIL() << "device must resolve before revocation";
    }
    static_cast<void>(store.revokeDevice("eugene", device->id, kRevokeAtMs));
    EXPECT_FALSE(store.deviceByTokenHash("hash-1").has_value());
}

TEST(Store, RevokeDevice) {
    Fixture fixture("revoke");
    auto store = fixture.makeStore();
    store.migrate();
    static_cast<void>(store.registerDevice("eugene", "hash-1", kBaseMs));
    const auto device = store.deviceByTokenHash("hash-1");
    if (!device.has_value()) {
        FAIL() << "device must resolve before revocation";
    }
    const auto deviceId = device->id;
    EXPECT_TRUE(store.revokeDevice("eugene", deviceId, kRevokeAtMs));
    // A second revoke is a no-op returning false.
    EXPECT_FALSE(store.revokeDevice("eugene", deviceId, kRevokeAgainMs));
}

TEST(Store, InviteStoredHashedNotPlaintext) {
    Fixture fixture("hashed");
    {
        auto store = fixture.makeStore();
        store.migrate();
        static_cast<void>(store.createInvite(std::nullopt, kHourTtlSeconds));
    } // Closing the store checkpoints WAL into the main database file.
    const auto raw = readFileBytes(fixture.dbPath);
    EXPECT_EQ(raw.find("FIXEDCODE"), std::string::npos)
        << "the plaintext invite code must never reach the database file";
    // The hash is stored as lowercase hex text.
    EXPECT_NE(raw.find(kFixedCodeHash), std::string::npos)
        << "sha256Hex(\"FIXEDCODE\") should be present";
}

TEST(Store, ListUsersAndDevices) {
    Fixture fixture("lists");
    auto store = fixture.makeStore();
    store.migrate();
    static_cast<void>(store.registerDevice("anna", "hash-a1", kBaseMs));
    static_cast<void>(store.registerDevice("eugene", "hash-e1", kBaseMs));
    static_cast<void>(
        store.registerDevice("eugene", "hash-e2", kSecondRegisterMs));
    const auto users = store.listUsers();
    ASSERT_EQ(users.size(), 2U);
    EXPECT_EQ(users[0], "anna");
    EXPECT_EQ(users[1], "eugene");
    const auto devices = store.listDevices("eugene");
    ASSERT_EQ(devices.size(), 2U);
    // Ordered by id: the older device is the revoked one.
    EXPECT_TRUE(devices[0].revoked);
    EXPECT_FALSE(devices[1].revoked);
}
