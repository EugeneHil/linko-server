// CLI implementation (Plan 3 Task 3): invite create (with join link and
// terminal QR), user list, device list/revoke. Everything above the store
// is plain argument handling; all persistence goes through Store.
#include "server/cli.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <qrcodegen.hpp>

#include "server/config.hpp"
#include "server/crypto.hpp"
#include "server/http.hpp"
#include "server/log.hpp"
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
constexpr std::int64_t kSecondsPerHour = 3600;

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
               "  device revoke <user> <id>\n",
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
    auto callSink = std::make_unique<NullSink>();
    auto msgSink = std::make_unique<NullSink>();
    WsHooks wsHooks;
    wsHooks.authenticate =
        [&store](const std::string &authorization) -> std::optional<Device> {
        HttpRequest request;
        request.authorization = authorization;
        return authenticateBearer(*store, request);
    };
    wsHooks.hub = hub.get();
    wsHooks.callSink = callSink.get();
    wsHooks.msgSink = msgSink.get();
    wsHooks.limits = config.limits;
    wsHooks.nowMs = []() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    };

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

    Listener listener(ioContext, sslContext, router, &wsHooks);
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

    // Validate the command shape before touching the config file: usage
    // errors must not depend on a config file existing.
    if (command == "invite" && !arguments.empty() &&
        arguments.front() == "create") {
        try {
            const auto config = loadConfig(configPath);
            return handleInviteCreate(
                std::vector<std::string>(arguments.begin() + 1,
                                         arguments.end()),
                config);
        } catch (const std::exception &error) {
            std::fprintf(stderr, "error: %s\n", error.what());
            return kExitError;
        }
    }
    if (command == "user" && arguments.size() == 1 &&
        arguments.front() == "list") {
        try {
            const auto config = loadConfig(configPath);
            return handleUserList(config);
        } catch (const std::exception &error) {
            std::fprintf(stderr, "error: %s\n", error.what());
            return kExitError;
        }
    }
    if (command == "device" && !arguments.empty() &&
        (arguments.front() == "list" || arguments.front() == "revoke")) {
        try {
            const auto config = loadConfig(configPath);
            if (arguments.front() == "list") {
                return handleDeviceList(
                    std::vector<std::string>(arguments.begin() + 1,
                                             arguments.end()),
                    config);
            }
            return handleDeviceRevoke(
                std::vector<std::string>(arguments.begin() + 1,
                                         arguments.end()),
                config);
        } catch (const std::exception &error) {
            std::fprintf(stderr, "error: %s\n", error.what());
            return kExitError;
        }
    }
    return usage();
}

} // namespace server
