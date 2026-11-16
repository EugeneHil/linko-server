# VPS deploy script (Plan 3 Task 10, spec 8 with the manual-deploy cut).
# Runs ON the VPS: builds linko-server and (re)installs the LinkoServer
# Windows service. Paths and service configuration only - secrets (the TLS
# key, the TURN secret) live in the VPS's own config.json and certs
# directory and never appear here; see docs/deploy.md.
param(
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
    [string]$ServiceName = "LinkoServer",
    [string]$ConfigPath = "$RepoRoot\config.json"
)

$ErrorActionPreference = "Stop"

if (-not $env:VCPKG_ROOT) {
    throw "VCPKG_ROOT must point at your vcpkg checkout (docs/deploy.md)."
}

Push-Location $RepoRoot
try {
    # 1. Build (Release). Manifest-mode vcpkg resolves boost-beast, openssl
    #    and sqlite3 from vcpkg.json on the first configure.
    cmake --preset windows
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($LASTEXITCODE)" }
    cmake --build --preset windows
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($LASTEXITCODE)" }

    $binary = Join-Path $RepoRoot "build\windows\Release\linko-server.exe"
    if (-not (Test-Path $binary)) {
        throw "built binary not found: $binary"
    }

    # 2. (Re)register the service. sc.exe needs the whole command line as
    #    ONE binPath= value; passing a single string variable keeps it
    #    intact. Absolute paths are required - services have no working
    #    directory of their own.
    $binPath = '"' + $binary + '" --config "' + $ConfigPath + '" run'
    sc.exe stop $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
    sc.exe create $ServiceName start= auto binPath= $binPath `
        DisplayName= "Linko signaling server"
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed ($LASTEXITCODE)" }

    # 3. Restart on crash: after 5 s, 30 s and 60 s; the failure counter
    #    resets after a day.
    sc.exe failure $ServiceName reset= 86400 `
        actions= restart/5000/restart/30000/restart/60000
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed ($LASTEXITCODE)" }

    sc.exe start $ServiceName
    if ($LASTEXITCODE -ne 0) { throw "sc.exe start failed ($LASTEXITCODE)" }
    sc.exe query $ServiceName
} finally {
    Pop-Location
}
