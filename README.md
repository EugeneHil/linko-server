# linko-server

Signaling and messaging server of **Linko**, a private 1:1 messenger with audio/video calls and file transfer. C++17; runs on a Windows VPS (product) and macOS (development). Uses [linko-core](https://github.com/EugeneHil/linko-core) as a submodule pinned to a tag for the protocol, the call state machine and hashing.

Design: `docs/superpowers/specs/2026-10-25-linko-design.md` in the [linko-apple](https://github.com/EugeneHil/linko-apple) repository. Deployment runbook: [docs/deploy.md](docs/deploy.md).

## Architecture

```
┌──────────────── iPhone / Mac (linko-apple workspace) ────────────────────┐
│  SwiftUI apps ─ Signaling (WSS client, SPKI pinning) ─ WebRTC media      │
└──────────────┬───────────────── WSS + HTTPS :443 ────────┬───────────────┘
               │                                           │ media / data (DTLS-SRTP):
               │                                           │ direct P2P, or relayed via TURN
┌──────────────▼───────────── Windows VPS ─────────────────▼───────────────┐
│ linko-server (C++17) ─► linko-core (same code)        coturn             │
│   ├─ /ws: signaling, chat, receipts, presence         UDP/TCP 3478       │
│   ├─ /api/v1/*: register, users, turn, files, calls   relay 49160–49200  │
│   ├─ SQLite: users, devices, invites, messages, files, call reports      │
│   └─ CLI: invite, user, device, calls, cert                              │
└──────────────────────────────────────────────────────────────────────────┘
```

Signaling, chat and receipts are JSON envelopes over TLS-terminated WebSocket (`linko-core` protocol v1); media and in-call files flow peer-to-peer or through coturn, never through this server.

## Module map

| Module (`src/`) | Responsibility |
|---|---|
| `http/listener` | TLS listener: HTTP/1.1 + WebSocket upgrade, streaming file uploads, request-line logging |
| `http/router`, `http/*_handler` | Routing and endpoints: `POST /api/v1/register`, `GET /api/v1/users`, `GET /api/v1/turn`, `GET/PUT /api/v1/files`, `POST /api/v1/calls/{id}` |
| `ws/session`, `ws/hub` | Authenticated WebSocket sessions, presence broadcast, per-device socket registry with connect hooks |
| `call_registry` | One `linko-core` call state machine per call: busy answers, ring/connect timers, relay routes, socket-drop cleanup |
| `messaging` | Message persistence, per-conversation `seq`, offline backlog, delivered/read receipts |
| `file_store`, `cleanup` | Server-side file storage (100 MB cap, per-user quota, TTL cleanup) |
| `store` | SQLite schema and migrations (users, devices, invites, messages, files, call reports) |
| `crypto`, `cert` | Random identifiers, SPKI pin, self-signed certificate generation |
| `throttle` | Auth-failure rate limiting |
| `config` | JSON config + `LINKO_*` environment variables |
| `cli` | `invite create`, `user list`, `device list/revoke`, `calls list/show`, `cert generate` |

## Configuration

One JSON file plus `LINKO_*` environment variables (env wins over file); see `config.example.json` with the shipped placeholders. Limits have defaults - a config file may override only what it cares about.

| JSON key | Env | Meaning |
|---|---|---|
| `bind` | `LINKO_BIND` | Listen address (default `0.0.0.0`) |
| `port` | `LINKO_PORT` | Listen port (default `443`) |
| `dataDir` | `LINKO_DATA_DIR` | SQLite database (`linko.db`) and stored files |
| `certFile` | `LINKO_TLS_CERT` | TLS certificate (PEM) |
| `keyFile` | `LINKO_TLS_KEY` | TLS private key (PEM) - never leaves the host |
| `turnSecret` | `LINKO_TURN_SECRET` | coturn REST shared secret (spec 4.6) |
| `publicHost` | `LINKO_PUBLIC_HOST` | Host name for invite links and TURN URIs |
| `turnUris` | - | TURN URIs handed to clients; derived from `publicHost:3478` when absent |
| `limits.*` | - | `maxFileBytes`, `userQuotaBytes`, `fileTtlDays`, `maxSocketsPerDevice`, `envelopesPerMinute`, `authFailsPerMinute`, `idleTimeoutSec`, `turnTtlSec` |

Unknown keys - top level or inside `limits` - are rejected with an error naming the key.

## Build and test

- **macOS (development):** `cmake --preset macos && cmake --build --preset macos && ctest --preset macos` - Homebrew `boost`, `openssl@3`, `sqlite3`; keg-only prefixes are hinted by the preset.
- **Windows (product):** `VCPKG_ROOT` set, then `cmake --preset windows && cmake --build --preset windows && ctest --preset windows` - dependencies resolve from the pinned `vcpkg.json` manifest (boost-beast 1.92.0, OpenSSL 3.6.5, SQLite 3.54.1).
- **Linux** is a development-only preset (`linux`), not a product platform.
- **One command:** `scripts/ci-local.sh [preset]` - build, tests, clang-format, clang-tidy, llvm-cov coverage report (macOS).
- **Submodule:** `git submodule update --init --recursive` after clone; the pin is a `linko-core` release tag (`v0.1.0`).

CI (`.github/workflows/ci.yml`) builds and tests both platforms, gates llvm-cov line coverage of the server sources at >= 80 %, and runs the lint checks; gitleaks scans every push and pull request.

## Wire contract notes

Pinned for any future third-party client:

- **Hex digests are lowercase** - file chunk SHA-256 digests and every other hex string produced by `linko-core` use lowercase `a-f`.
- **SPKI pin** - `base64(SHA-256(SPKI DER))` of the server certificate (standard alphabet with padding), carried by the `linko://join?...` link and validated by the clients.

## Roadmap

- Tag-triggered CI deploy (deploy is manual today - [docs/deploy.md](docs/deploy.md)).
- Durable file logging (logs go to stderr today).
- Conversation-scoped presence (presence is per-user today).
- Multi-device for one user (one live socket per device today).
