# Deploying linko-server to the VPS

Manual deploy (design spec 8, applied cut #1: tag-triggered CI deploy stays
roadmap). The VPS is a Windows Server machine that runs the **LinkoServer**
signaling Windows service (this repo) plus **coturn** (TURN relay). In v0.1
coturn is started by hand from an open RDP/SSH session per the TURN runbook
([docs/turn-setup.md](https://github.com/EugeneHil/linko-apple/blob/develop/docs/turn-setup.md)
in the linko-apple repo); it is not registered as a Windows service yet, so
it dies with that session - keeping the session open is part of running the
scenario. Registering coturn as a proper service (spec 8's "server and TURN
registered as Windows services") stays roadmap. Nothing in this runbook
auto-touches the VPS - the steps are executed together with the owner.

## 1. Prerequisites

- Windows Server 2022 or newer (the LNK-3 spike ran on Windows Server 2022)
  with the VS Build Tools (C++ workload, Windows SDK) and CMake >= 3.28 on
  PATH.
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

Create the server config **outside the repo tree**, e.g.
`C:\linko\config.json`: it carries the TURN shared secret, and secrets do
not belong inside a git working tree even though `.gitignore` also lists
`config.json`, `server.crt` and `certs/` as a safety net. `deploy.ps1 -ConfigPath`
(step 5) accepts any path. Copy `config.example.json` as the starting point
and fill it in - note that the example's relative paths (`"dataDir": "data"`,
`"certFile": "certs/server.crt"`) only work for local runs from the repo
root; they are placeholders, not a deployable shape. The service has no
working directory of its own, so **every path in the deployed config must
be absolute** (forward slashes keep the JSON clean, as below);
spec 3 assumes no DNS domain in v0.1, so `publicHost` is the raw VPS IP
(self-signed cert + SPKI pinning make an IP as trustworthy as a name):

```json
{
  "port": 443,
  "dataDir": "C:/linko/data",
  "certFile": "C:/linko/certs/server.crt",
  "keyFile": "C:/linko/certs/server.key",
  "turnSecret": "<coturn's static-auth-secret, see below>",
  "publicHost": "<vps-public-ip>",
  "turnUris": ["turn:<vps-public-ip>:3478?transport=udp",
               "turn:<vps-public-ip>:3478?transport=tcp"]
}
```

**TURN shared secret - one source of truth.** `setup-turn.ps1` (TURN
runbook, section 2) generates a 32-byte hex `static-auth-secret` in coturn's
`turnserver.conf` on its first run and keeps it on reruns; it is never
printed. Copy **that same hex** into `config.json`'s "turnSecret" -
copy-paste only, never retype (Base64 look-alikes silently break the HMAC).
The secret never leaves the VPS (design spec 6). If you generate the secret
yourself instead, edit `turnserver.conf` and restart coturn so both sides
stay byte-identical.

## 4. Certificate (generated on the VPS)

The TLS key is generated **on the VPS and never leaves it** (design spec 6):

```powershell
.\build\windows\Release\linko-server.exe cert generate --out C:\linko\certs
```

(available after the first build in step 5). This writes a self-signed
ECDSA P-256 pair - `server.crt` (world-readable) and `server.key`
(owner-only) - and prints the SPKI pin, a public fingerprint that goes into
every join link. Regenerating replaces the pair and invalidates old pins.
Keep the cert pair next to the config, outside the repo tree
(`C:\linko\certs` above).

## 5. Build, install, start

```powershell
cd C:\linko-server
.\scripts\deploy.ps1 -ConfigPath C:\linko\config.json
```

The script configures and builds the Release binary, re-registers the
`LinkoServer` service via `sc.exe` (command line
`linko-server.exe --config C:\linko\config.json run`) with a
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

## 7. First invites

```powershell
.\build\windows\Release\linko-server.exe --config C:\linko\config.json invite create --user eugene
.\build\windows\Release\linko-server.exe --config C:\linko\config.json invite create --user anna
```

The command prints the `linko://join?...` link with the certificate pin
(plus a terminal QR that v0.1 apps cannot scan - onboarding is paste-only,
plan cut #4). Copy the link **text** and paste it into the device's
onboarding field; each invite code is single-use and expires in 24 h. v0.1
allows one device per user (spec 4.5 - a new invite for the same username
revokes that user's old device), so create one invite per **user**: the
scenario needs two, `eugene` and `anna` (see the v0.1 acceptance scenario,
[docs/e2e-checklist.md](e2e-checklist.md)).

## 8. Logs

The server writes structured lines to **stderr**: request lines
`addr method path status duration_ms` and short event lines
(`listening <bind:port>`). Per the design spec 6 it never logs tokens,
invite codes, Authorization values, message bodies, SDP or ICE credentials.

The Windows service manager discards a service's stderr and `deploy.ps1`
does not redirect it, so a service-mode run leaves **no readable log** -
neither for diagnostics nor for the request-line evidence the e2e checklist
(items 1, 7, 9) needs. For diagnostics and checklist evidence stop the
service and run the same command line in a console:

```powershell
sc.exe stop LinkoServer
.\build\windows\Release\linko-server.exe --config C:\linko\config.json run
```

(Capture the checklist log lines from this console while the scenario runs;
`sc.exe start LinkoServer` afterwards.) Durable file logging stays roadmap
(spec 8 cut #1).
