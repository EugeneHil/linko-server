// CLI implementation (Plan 3 Task 3): invite create (with join link and
// terminal QR), user list, device list/revoke. Everything above the store
// is plain argument handling; all persistence goes through Store.
#include "server/cli.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <qrcodegen.hpp>

#include <nlohmann/json.hpp>

#include "server/call_registry.hpp"
#include "server/config.hpp"
#include "server/crypto.hpp"
#include "server/file_store.hpp"
#include "server/http.hpp"
#include "server/log.hpp"
#include "server/messaging.hpp"
#include "server/store.hpp"
#include "server/throttle.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace asio = boost::asio;
namespace ssl = asio::ssl;

namespace server {
namespace {

constexpr int kExitOk = 0;
constexpr int kExitError = 1;
constexpr int kExitUsage = 2;
constexpr int kDefaultInviteTtlHours = 24;
constexpr std::size_t kInviteCodeBytes = 16;
// The default `cert generate --out` directory: the paths config.example.json
// ships (certs/server.crt, certs/server.key).
constexpr const char *kDefaultCertDir = "certs";
constexpr std::int64_t kSecondsPerHour = 3600;
// The TTL cleanup cadence (Plan 3 Task 8): once at startup, then daily.
constexpr int kCleanupIntervalHours = 24;

// Epoch milliseconds from the system clock - the inline lambdas below bind
// it where an injectable clock slot exists.
auto systemNowMs() -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// UTF-8 half-block characters for the terminal QR code (upper half filled,
// lower half filled, full block).
constexpr const char *kBlockUpper = "\xE2\x96\x80";
constexpr const char *kBlockLower = "\xE2\x96\x84";
constexpr const char *kBlockFull = "\xE2\x96\x88";

auto usage() -> int {
    std::fputs("usage: linko-server [--config <path>] <command> [...]\n"
               "\n"
               "config: configuration file, default \"config.json\"; the\n"
               "        database lives in its dataDir as linko.db\n"
               "\n"
               "commands:\n"
               "  invite create [--user <name>] [--ttl-hours N=24]\n"
               "                [--host <h>] [--port <p>] [--cert <pem>]\n"
               "                Print a one-time join link and its QR code.\n"
               "  user list\n"
               "  device list <user>\n"
               "  device revoke <user> <id>\n"
               "  calls list\n"
               "                Print stored end-of-call quality reports.\n"
               "  calls show <callId>\n"
               "                Print the stored reports of one call.\n"
               "  cert generate [--out <dir>]\n"
               "                Create a self-signed ECDSA P-256 certificate\n"
               "                (CN=linko, valid 3650 days) and key; print\n"
               "                the SPKI pin.\n",
               stderr);
    return kExitUsage;
}

auto openStore(const Config &config) -> std::unique_ptr<Store> {
    auto store = std::make_unique<Store>(
        config.dataDir + "/linko.db",
        []() -> std::string { return randomHex(kInviteCodeBytes); });
    store->migrate();
    return store;
}

// Renders `text` as a terminal QR code with UTF-8 half-blocks: one text row
// covers two QR rows (top pixel = upper half of the block character).
void printQr(const std::string &text) {
    const qrcodegen::QrCode code = qrcodegen::QrCode::encodeText(
        text.c_str(), qrcodegen::QrCode::Ecc::LOW);
    const int size = code.getSize();
    for (int rowY = 0; rowY < size; rowY += 2) {
        std::string line;
        line.reserve((static_cast<std::size_t>(size) * 3) + 1);
        for (int rowX = 0; rowX < size; ++rowX) {
            const bool top = code.getModule(rowX, rowY);
            const bool bottom =
                rowY + 1 < size && code.getModule(rowX, rowY + 1);
            if (top && bottom) {
                line += kBlockFull;
            } else if (top) {
                line += kBlockUpper;
            } else if (bottom) {
                line += kBlockLower;
            } else {
                line += ' ';
            }
        }
        line += '\n';
        std::fputs(line.c_str(), stdout);
    }
}

// Reads an option value that must follow `flag`; returns nullopt when the
// flag is absent, throws on a missing value (a usage error).
auto optionValue(const std::vector<std::string> &arguments,
                 const std::string &flag) -> std::optional<std::string> {
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        if (arguments[index] == flag) {
            if (index + 1 >= arguments.size()) {
                throw std::runtime_error(flag + " needs a value");
            }
            return arguments[index + 1];
        }
    }
    return std::nullopt;
}

// Starts the server: TLS listener on config.bind:config.port with the
// registration route wired. Runs the io_context on the calling thread until
// the process is stopped.
auto handleRun(const std::string &configPath) -> int {
    const auto config = loadConfig(configPath);
    asio::io_context ioContext;
    ssl::context sslContext{ssl::context::tls_server};
    sslContext.use_certificate_chain_file(config.certFile);
    sslContext.use_private_key_file(config.keyFile, ssl::context::pem);

    auto store = openStore(config);
    Throttle throttle(config.limits.authFailsPerMinute, []() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    });
    auto hub = std::make_unique<Hub>([]() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    });
    // The call registry (Plan 3 Task 6): one core state machine per call,
    // busy answers, ring timeouts, relay and socket-drop cleanup. The
    // messaging sink (Plan 3 Task 7): persistence, seq assignment, offline
    // delivery and receipts.
    auto registry = std::make_unique<CallRegistry>(
        *hub, config.limits,
        []() -> std::int64_t {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        },
        ioContext.get_executor());
    auto messaging =
        std::make_unique<Messaging>(*store, *hub, []() -> std::int64_t {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        });
    // Reconnects push the undelivered backlog (receipt-keyed); the hook
    // fires outside the hub lock, so the push may send through the hub.
    hub->setConnectHook([&messaging](const std::string &user) -> void {
        messaging->onConnect(user);
    });
    // File storage (Plan 3 Task 8): the upload/download endpoints and the
    // TTL cleanup - once at startup, then every 24 hours.
    auto files = std::make_unique<FileStore>(config.dataDir);
    cleanupExpiredFiles(
        *store, *files, config.limits.fileTtlDays, []() -> std::int64_t {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        }());
    auto cleanupTimer = std::make_shared<asio::steady_timer>(ioContext);
    std::function<void()> armCleanup = [&]() -> void {
        cleanupTimer->expires_after(std::chrono::hours(kCleanupIntervalHours));
        cleanupTimer->async_wait(
            [&store, &files, &config, &armCleanup,
             cleanupTimer](const boost::system::error_code &error) -> void {
                if (error) {
                    return; // the io_context stopped: shutdown
                }
                cleanupExpiredFiles(
                    *store, *files, config.limits.fileTtlDays,
                    []() -> std::int64_t {
                        return std::chrono::duration_cast<
                                   std::chrono::milliseconds>(
                                   std::chrono::system_clock::now()
                                       .time_since_epoch())
                            .count();
                    }());
                armCleanup();
            });
    };
    armCleanup();
    WsHooks wsHooks;
    wsHooks.authenticate =
        [&store](const std::string &authorization) -> std::optional<Device> {
        HttpRequest request;
        request.authorization = authorization;
        return authenticateBearer(*store, request);
    };
    wsHooks.hub = hub.get();
    wsHooks.callSink = registry.get();
    wsHooks.msgSink = messaging.get();
    wsHooks.limits = config.limits;
    wsHooks.nowMs = []() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    };
    UploadHooks uploadHooks;
    uploadHooks.store = store.get();
    uploadHooks.files = files.get();
    uploadHooks.limits = config.limits;
    uploadHooks.nowMs = wsHooks.nowMs;

    Router router;
    router.add("POST", "/api/v1/register",
               [&store, &throttle](const HttpRequest &request) -> HttpResponse {
                   return handleRegister(*store, throttle, request);
               });
    router.add("GET", "/api/v1/users",
               [&store](const HttpRequest &request) -> HttpResponse {
                   return handleUsers(*store, request);
               });
    router.add("GET", "/api/v1/turn",
               [&config, &store](const HttpRequest &request) -> HttpResponse {
                   return handleTurn(config, *store, request);
               });
    // GET /api/v1/files/{id}; PUT /api/v1/files is intercepted by the
    // listener (the body streams, it is not dispatched through the router).
    router.addPrefix(
        "GET", "/api/v1/files/",
        [&store, &files](const HttpRequest &request) -> HttpResponse {
            return handleFileDownload(*store, *files, request);
        });
    // Call quality reports (Plan 3 Task 9): the stored body is the client's
    // summary verbatim; received_at comes from the system clock.
    router.addPrefix("POST", "/api/v1/calls/",
                     [&store](const HttpRequest &request) -> HttpResponse {
                         return handleCallReport(*store, request,
                                                 systemNowMs());
                     });

    Listener listener(ioContext, sslContext, router, &wsHooks, &uploadHooks);
    listener.listen(config.bind, static_cast<unsigned short>(config.port));
    logEvent("listening", config.bind + ":" + std::to_string(config.port));
    ioContext.run();
    return kExitOk;
}

auto handleInviteCreate(const std::vector<std::string> &arguments,
                        const Config &config) -> int {
    std::optional<std::string> user;
    int ttlHours = kDefaultInviteTtlHours;
    std::string host = config.publicHost;
    int port = config.port;
    std::string certFile = config.certFile;
    try {
        if (const auto value = optionValue(arguments, "--user")) {
            user = *value;
        }
        if (const auto value = optionValue(arguments, "--ttl-hours")) {
            ttlHours = std::stoi(*value);
        }
        if (const auto value = optionValue(arguments, "--host")) {
            host = *value;
        }
        if (const auto value = optionValue(arguments, "--port")) {
            port = std::stoi(*value);
        }
        if (const auto value = optionValue(arguments, "--cert")) {
            certFile = *value;
        }
    } catch (const std::exception &) {
        std::fputs("error: invalid value for an invite create option\n",
                   stderr);
        return kExitUsage;
    }

    const auto store = openStore(config);
    const auto invite = store->createInvite(
        user, static_cast<std::int64_t>(ttlHours) * kSecondsPerHour);

    std::string link =
        "linko://join?host=" + host + "&port=" + std::to_string(port);
    if (!certFile.empty()) {
        link += "&pin=" + spkiPinOfCertFile(certFile);
    }
    link += "&code=" + invite.code;

    // The invite code is a secret shown exactly once: this stdout line and
    // the QR are the only places it ever appears (design spec 4.5).
    std::fputs((link + "\n").c_str(), stdout);
    printQr(link);
    return kExitOk;
}

auto handleUserList(const Config &config) -> int {
    const auto store = openStore(config);
    for (const auto &user : store->listUsers()) {
        std::fputs((user + "\n").c_str(), stdout);
    }
    return kExitOk;
}

auto handleDeviceList(const std::vector<std::string> &arguments,
                      const Config &config) -> int {
    if (arguments.empty()) {
        return usage();
    }
    const auto store = openStore(config);
    for (const auto &device : store->listDevices(arguments.front())) {
        std::fputs((std::to_string(device.id) + " " +
                    (device.revoked ? "revoked" : "active") + "\n")
                       .c_str(),
                   stdout);
    }
    return kExitOk;
}

auto handleDeviceRevoke(const std::vector<std::string> &arguments,
                        const Config &config) -> int {
    if (arguments.size() <= 1) {
        return usage();
    }
    std::int64_t deviceId = 0;
    try {
        deviceId = std::stoll(arguments[1]);
    } catch (const std::exception &) {
        std::fputs("error: device id must be an integer\n", stderr);
        return kExitUsage;
    }
    const auto store = openStore(config);
    if (store->revokeDevice(
            arguments[0], deviceId,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count())) {
        std::fputs("revoked\n", stdout);
    } else {
        std::fputs("already revoked or unknown device\n", stdout);
    }
    return kExitOk;
}

// The display value of one report field (Plan 3 Task 9): strings and
// numbers print as-is, anything else (missing, null, nested) prints as
// "-"; report bodies are app-defined, so every lookup is tolerant.
auto reportField(const nlohmann::json &report, const char *key) -> std::string {
    if (!report.is_object() || !report.contains(key)) {
        return "-";
    }
    const auto &value = report.at(key);
    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_number()) {
        return value.dump();
    }
    return "-";
}

// One row per stored report: the server-side facts (call id, sender,
// received_at) plus the fields the list cares about, derived from the
// stored JSON with tolerant lookups.
auto handleCallList(const Config &config) -> int {
    const auto store = openStore(config);
    for (const auto &row : store->callReports()) {
        const auto report =
            nlohmann::json::parse(row.reportJson, nullptr, false);
        std::fputs((row.callId + " " + row.fromUser + " " +
                    std::to_string(row.receivedAt) +
                    " duration=" + reportField(report, "duration") +
                    " setupMs=" + reportField(report, "setupMs") +
                    " candidate=" + reportField(report, "candidate") +
                    " endReason=" + reportField(report, "endReason") + "\n")
                       .c_str(),
                   stdout);
    }
    return kExitOk;
}

// Prints every stored report of `callId` verbatim, one per line; an
// unknown call id prints nothing and succeeds (like an empty user list).
auto handleCallShow(const Config &config, const std::string &callId) -> int {
    const auto store = openStore(config);
    for (const auto &row : store->callReports()) {
        if (row.callId == callId) {
            std::fputs((row.reportJson + "\n").c_str(), stdout);
        }
    }
    return kExitOk;
}

// The calls subcommands (Plan 3 Task 9). nullopt when `command` is not a
// calls command at all - the caller falls through to usage().
auto handleCallsCommand(const std::string &command,
                        const std::vector<std::string> &arguments,
                        const std::string &configPath) -> std::optional<int> {
    if (command != "calls" || arguments.empty() ||
        (arguments.front() != "list" && arguments.front() != "show")) {
        return std::nullopt;
    }
    if (arguments.front() == "show" && arguments.size() < 2) {
        return usage();
    }
    try {
        const auto config = loadConfig(configPath);
        if (arguments.front() == "list") {
            return handleCallList(config);
        }
        return handleCallShow(config, arguments[1]);
    } catch (const std::exception &error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return kExitError;
    }
}

// The cert subcommand (Plan 3 Task 10). nullopt when `command` is not a
// cert command at all - the caller falls through to usage(). Deliberately
// never touches the config file: certificate generation must work on a
// fresh VPS before any configuration exists. The pin is a public key
// fingerprint, safe to print and to embed in invite links.
auto handleCertCommand(const std::string &command,
                       const std::vector<std::string> &arguments)
    -> std::optional<int> {
    if (command != "cert" || arguments.empty() ||
        arguments.front() != "generate") {
        return std::nullopt;
    }
    std::string outDir = kDefaultCertDir;
    try {
        outDir = optionValue(arguments, "--out").value_or(kDefaultCertDir);
    } catch (const std::exception &) {
        std::fputs("error: --out needs a value\n", stderr);
        return kExitUsage;
    }
    try {
        const auto paths = generateSelfSignedCert(outDir);
        const std::string pin = spkiPinOfCertFile(paths.certFile);
        std::fputs(("cert: " + paths.certFile + "\n").c_str(), stdout);
        std::fputs(("key: " + paths.keyFile + "\n").c_str(), stdout);
        std::fputs(("pin: " + pin + "\n").c_str(), stdout);
        return kExitOk;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return kExitError;
    }
}

// The config-backed administration subcommands (Plan 3 Task 3): invite
// create, user list, device list/revoke. Every shape check happens before
// loadConfig, so usage errors never depend on the config file existing.
// nullopt when `command` is not one of them - the caller falls through to
// usage().
auto handleAdminCommand(const std::string &command,
                        const std::vector<std::string> &arguments,
                        const std::string &configPath) -> std::optional<int> {
    const bool isInviteCreate = command == "invite" && !arguments.empty() &&
                                arguments.front() == "create";
    const bool isUserList = command == "user" && arguments.size() == 1 &&
                            arguments.front() == "list";
    const bool isDevice =
        command == "device" && !arguments.empty() &&
        (arguments.front() == "list" || arguments.front() == "revoke");
    if (!isInviteCreate && !isUserList && !isDevice) {
        return std::nullopt;
    }
    try {
        const auto config = loadConfig(configPath);
        if (isInviteCreate) {
            return handleInviteCreate(
                std::vector<std::string>(arguments.begin() + 1,
                                         arguments.end()),
                config);
        }
        if (isUserList) {
            return handleUserList(config);
        }
        const std::vector<std::string> tail(arguments.begin() + 1,
                                            arguments.end());
        if (arguments.front() == "list") {
            return handleDeviceList(tail, config);
        }
        return handleDeviceRevoke(tail, config);
    } catch (const std::exception &error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return kExitError;
    }
}

} // namespace

auto runCli(int argc, char **argv) -> int {
    std::string configPath = "config.json";
    int index = 1;
    if (index < argc && std::strcmp(argv[index], "--config") == 0) {
        if (index + 1 >= argc) {
            return usage();
        }
        configPath = argv[index + 1];
        index += 2;
    }
    if (index >= argc) {
        return usage();
    }
    const std::string command = argv[index];
    const std::vector<std::string> arguments(argv + index + 1, argv + argc);

    if (command == "run" && arguments.empty()) {
        try {
            return handleRun(configPath);
        } catch (const std::exception &error) {
            std::fprintf(stderr, "error: %s\n", error.what());
            return kExitError;
        }
    }

    // The admin subcommands validate their shape inside the helper before
    // touching the config file: usage errors must not depend on a config
    // file existing.
    if (const auto handled =
            handleAdminCommand(command, arguments, configPath)) {
        return *handled;
    }
    if (const auto handled =
            handleCallsCommand(command, arguments, configPath)) {
        return *handled;
    }
    if (const auto handled = handleCertCommand(command, arguments)) {
        return *handled;
    }
    return usage();
}

} // namespace server
