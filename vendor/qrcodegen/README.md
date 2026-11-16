# Vendored: qrcodegen (Nayuki QR-Code-generator)

- Upstream: https://github.com/nayuki/QR-Code-generator (MIT License)
- Pinned release: **v1.8.0** — `cpp/qrcodegen.hpp` and `cpp/qrcodegen.cpp`
  copied verbatim from that tag; do not reformat. The two files build as the
  `vendor_qrcodegen` CMake target without the repository's warnings-as-errors
  flags (upstream code is not held to our lint rules); headers are included
  as SYSTEM includes for the same reason.
- Used by: `invite create` CLI — renders the `linko://join?...` link as a
  terminal QR code (UTF-8 half-blocks), design spec §4.5.
- Upgrade path: replace both files from a newer release tag and update this
  note. Recorded in ADR-0003 (linko-apple, `docs/adr/0003-server-dependencies.md`)
  under Consequences, alongside linko-core's vendored SHA-256 (ADR-0002).
