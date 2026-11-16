# Deploying linko-server to the VPS

Manual deploy (design spec 8, applied cut #1: tag-triggered CI deploy stays
roadmap). The VPS is a Windows Server machine that runs two services: the
**LinkoServer** signaling service (this repo) and **coturn** (TURN relay,
set up once via [docs/turn-setup.md](../../linko-apple/docs/turn-setup.md) in
the linko-apple repo). Nothing in this runbook auto-touches the VPS - the
steps are executed together with the owner.

## 1. Prerequisites

- Windows Server with the VS Build Tools (C++ workload, Windows SDK) and
  CMake >= 3.28 on PATH.
- Git.
- A vcpkg checkout, bootstrapped once:

  ```powershell
  git clone https://github.com/microsoft/vcpkg C:\vcpkg
  C:\vcpkg\bootstrap-vcpkg.bat
  setx /M VCPKG_ROOT C:\vcpkg
  ```

  Open a new terminal afterwards. The dependency manifest (vcpkg.json)
  resolves boost-beast, OpenSSL and SQLite3 on the first configure.

## 2. Get the code

```powershell
git clone https://github.com/EugeneHil/linko-server C:\linko-server
cd C:\linko-server
git submodule update --init --recursive
```

## 3. Configuration

Copy `config.example.json` to `C:\linko-server\config.json` and fill it in.
The service has no working directory of its own, so **every path in the
config must be absolute** (forward slashes keep the JSON clean):

```json
{
  "port": 443,
  "dataDir": "C:/linko-server/data",
  "certFile": "C:/linko-server/certs/server.crt",
  "keyFile": "C:/linko-server/certs/server.key",
  "publicHost": "linko.example.com",
  "turnUris": ["turn:linko.example.com:3478?transport=udp",
               "turn:linko.example.com:3478?transport=tcp"]
}
```

Generate the TURN shared secret on the VPS and put it into both
`config.json` ("turnSecret") and coturn's config - it never leaves the VPS
(design spec 6):

```powershell
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = [byte[]]::new(32)
$rng.GetBytes($bytes)
[BitConverter]::ToString($bytes).Replace("-", "").ToLower()
```

## 4. Certificate (generated on the VPS)

The TLS key is generated **on the VPS and never leaves it** (design spec 6):

```powershell
.\build\windows\Release\linko-server.exe cert generate --out C:\linko-server\certs
```

(available after the first build in step 5). This writes a self-signed
ECDSA P-256 pair - `server.crt` (world-readable) and `server.key`
(owner-only) - and prints the SPKI pin, a public fingerprint that goes into
every join link. Regenerating replaces the pair and invalidates old pins.

## 5. Build, install, start

```powershell
cd C:\linko-server
.\scripts\deploy.ps1
```

The script configures and builds the Release binary, re-registers the
`LinkoServer` service via `sc.exe` (command line
`linko-server.exe --config C:\linko-server\config.json run`) with a
restart-on-crash policy (5 s / 30 s / 60 s, counter reset daily) and starts
it. Re-run it after every `git pull` + `git submodule update` to update.

## 6. Firewall

The VPS keeps ports open for signaling and the TURN fallback (ADR-0001):

```powershell
New-NetFirewallRule -DisplayName "Linko signaling" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "Linko TURN"       -Direction Inbound -Protocol UDP -LocalPort 3478 -Action Allow
New-NetFirewallRule -DisplayName "Linko TURN TCP"   -Direction Inbound -Protocol TCP -LocalPort 3478 -Action Allow
New-NetFirewallRule -DisplayName "Linko TURN relay" -Direction Inbound -Protocol UDP -LocalPort 49160-49200 -Action Allow
```

coturn's own port configuration must stay inside 49160-49200.

## 7. First invite

```powershell
.\build\windows\Release\linko-server.exe --config C:\linko-server\config.json invite create --user eugene
```

The command prints the `linko://join?...` link with the certificate pin and
a QR code, exactly once - scan it on the device. Repeat per device; the
first device of a new user gets its own invite (see the v0.1 acceptance
scenario, [docs/e2e-checklist.md](e2e-checklist.md)).

## 8. Logs

The server writes structured lines to **stderr**: request lines
`addr method path status duration_ms` and short event lines
(`listening <bind:port>`). Per the design spec 6 it never logs tokens,
invite codes, Authorization values, message bodies, SDP or ICE credentials.

The Windows service manager discards a service's stderr, so for diagnostics
stop the service and run the same command line in a console:

```powershell
sc.exe stop LinkoServer
.\build\windows\Release\linko-server.exe --config C:\linko-server\config.json run
```

Durable file logging stays roadmap (spec 8 cut #1).
