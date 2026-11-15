# CLAUDE.md

Linko: a private 1:1 messenger for iPhone and Mac with audio/video calls and file transfer. Design: `linko-apple/docs/superpowers/specs/2026-10-25-linko-design.md`.

## Rules (non-negotiable)

- **TDD:** write the failing test first, watch it fail, then implement. No production code without a test that failed first.
- **Branches:** never commit or push to `main` or `develop`. Work in `feature/LNK-<n>-<slug>`, `fix/…`, `chore/…`, `docs/…`, `spike/…`. PRs target `develop`; merge with `gh pr merge` only after checks are green and the owner approved. Releases: PR `develop → main` + tag `vX.Y.Z`.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`, `ci:`, `build:`, `perf:`). Never `--no-verify`, never skip hooks, never force push.
- **Secrets:** never read, write or commit `.env*` (except `.env.example`), `*.pem`, `*.key`, `*.p12`, `*.p8`, `*.cer`, `*.mobileprovision`, `config.local.json`. Configuration goes into `*.example*` templates with placeholders. A private key never leaves the host it belongs to.
- **Logging:** never log tokens, invite codes, `Authorization` values, message bodies, SDP or ICE credentials.
- **Dependencies:** no new dependency without an ADR in `docs/adr/`; versions pinned exactly.
- **Swift:** Swift Concurrency only (async/await, actors, `AsyncStream`/`AsyncSequence`, `Task`); no GCD, `OperationQueue`, Combine or completion handlers in our code. Callback and delegate APIs (WebRTC, CallKit, `URLSessionWebSocketTask`, `NWPathMonitor`, `AVAudioSession` notifications) are wrapped once at the boundary. Where an Apple API demands a synchronous answer (a CallKit action must be fulfilled or failed), the boundary adapter does exactly that and nothing more. No force unwraps, no `try!`.
- **Warnings are errors** in every language.
- **Docs:** English.

## Guard hook

`tooling/claude/guard.py` runs before every Read/Edit/Write/Bash call and enforces the secret and branch rules above. Do not disable it. Tests: `python3 -I -B -m unittest discover -s tooling/claude`.

## Stack

- **Build:** CMake ≥ 3.28 with presets. `cmake --preset macos && cmake --build --preset macos && ctest --preset macos` (macOS dev); `cmake --preset windows && cmake --build --preset windows && ctest --preset windows` (Windows product — requires `VCPKG_ROOT`, deps resolve from `vcpkg.json`: boost-beast 1.92.0, openssl 3.6.5#2, sqlite3 3.54.1, builtin-baseline `4702e381dbbd9b54d3f7e1eb565cd8981c1814cd`); `linux` preset is a dev build only. `coverage` preset reports llvm-cov line coverage (macOS).
- **Targets:** `server_lib` (all server logic — the only thing the ≥ 80 % coverage gate measures), `linko-server` (CLI exe), `linko_server_tests`-registered suites via `linko_add_test(<name> <sources…>)` in `tests/CMakeLists.txt`. The `linko-core` submodule under `external/linko-core` brings `linko_core`, GoogleTest (`gtest_main`) and nlohmann_json (ADR-0002); its own suites build and run in this tree and must stay green.
- **Submodule:** `git submodule update --init --recursive` after clone. The pin is `7763608` (interim, develop HEAD) until tag `v0.1.0` exists — then re-pin to the tag: `git -C external/linko-core fetch --tags && git -C external/linko-core checkout v0.1.0 && git add external/linko-core`. Dependencies rationale: ADR-0003 in the linko-apple repo (`docs/adr/0003-server-dependencies.md`).
- **One command:** `scripts/ci-local.sh [preset]` — configure + build + ctest, clang-format, clang-tidy (server sources only; the submodule is excluded), llvm-cov coverage report on macOS.
