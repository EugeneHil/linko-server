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
