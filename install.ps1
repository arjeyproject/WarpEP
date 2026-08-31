<#
.SYNOPSIS
    WarpEP by ArJey - one-line installer for Windows (CMD, PowerShell, Terminal).

.DESCRIPTION
    Installs the zero-dependency WarpEP scanner into %LOCALAPPDATA%\WarpEP and puts
    a `warpep` command on your PATH. Python 3.8+ is installed via winget if missing.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"

.EXAMPLE
    # install and scan straight away
    $env:WARPEP_RUN=1; irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex
#>
[CmdletBinding()]
param(
    [string]$Ref = $(if ($env:WARPEP_REF) { $env:WARPEP_REF } else { "main" }),
    [switch]$Run = $([bool]$env:WARPEP_RUN),
    [switch]$Fast,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$Repo = "arjeyproject/WarpEP"
$Root = Join-Path $env:LOCALAPPDATA "WarpEP"
$Lib = Join-Path $Root "lib"
$Bin = Join-Path $Root "bin"

function Write-Banner {
    $art = @"
 __        __                 _____ ____
 \ \      / /_ _ _ __ _ __   | ____|  _ \
  \ \ /\ / / _`` | '__| '_ \  |  _| | |_) |
   \ V  V / (_| | |  | |_) | | |___|  __/
    \_/\_/ \__,_|_|  | .__/  |_____|_|
                     |_|
"@
    Write-Host $art -ForegroundColor Cyan
    Write-Host "  WarpEP by ArJey - real Cloudflare WARP endpoint scanner`n" -ForegroundColor White
}
function Say  ($m) { Write-Host "* $m" -ForegroundColor Cyan }
function Good ($m) { Write-Host "+ $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "! $m" -ForegroundColor Yellow }
function Fail ($m) { Write-Host "x $m" -ForegroundColor Red; exit 1 }

function Get-Python {
    foreach ($candidate in @("python", "python3", "py")) {
        $exe = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $probe = & $candidate -c "import sys; print(1 if sys.version_info >= (3,8) else 0)" 2>$null
            if ($probe -eq "1") { return $exe.Source }
        } catch { }
    }
    return $null
}

function Install-Python {
    Warn "Python 3.8+ was not found, installing it with winget"
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Fail "winget is unavailable. Install Python from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and re-run this installer."
    }
    winget install --id Python.Python.3.12 --source winget --accept-package-agreements --accept-source-agreements --silent | Out-Null
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $python = Get-Python
    if (-not $python) { Fail "Python still not visible. Close this window, open a new one and re-run the installer." }
    return $python
}

Write-Banner

if ($Uninstall) {
    if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -like "*$Bin*") {
        $cleaned = ($userPath.Split(';') | Where-Object { $_ -and $_ -ne $Bin }) -join ';'
        [System.Environment]::SetEnvironmentVariable("Path", $cleaned, "User")
    }
    Good "WarpEP removed"
    exit 0
}

$python = Get-Python
if (-not $python) { $python = Install-Python }
Say "python: $((& $python -V) -join '') ($python)"

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("warpep-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $zip = Join-Path $temp "src.zip"
    Say "downloading $Repo@$Ref"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $downloaded = $false
    foreach ($kind in @("heads", "tags")) {
        try {
            Invoke-WebRequest -Uri "https://codeload.github.com/$Repo/zip/refs/$kind/$Ref" -OutFile $zip -UseBasicParsing
            $downloaded = $true
            break
        } catch { }
    }
    if (-not $downloaded) { Fail "download failed: check your connection or -Ref value" }

    Expand-Archive -Path $zip -DestinationPath $temp -Force
    $src = Get-ChildItem -Path $temp -Directory | Where-Object { $_.Name -like "WarpEP-*" } | Select-Object -First 1
    if (-not $src -or -not (Test-Path (Join-Path $src.FullName "warpep"))) { Fail "the downloaded archive is missing the warpep package" }

    New-Item -ItemType Directory -Path $Lib, $Bin -Force | Out-Null
    if (Test-Path (Join-Path $Lib "warpep")) { Remove-Item -Recurse -Force (Join-Path $Lib "warpep") }
    Copy-Item -Recurse (Join-Path $src.FullName "warpep") (Join-Path $Lib "warpep")
    Copy-Item (Join-Path $src.FullName "LICENSE") (Join-Path $Lib "LICENSE") -ErrorAction SilentlyContinue

    # CMD shim, so `warpep` works in cmd.exe, PowerShell and Windows Terminal alike.
    @"
@echo off
setlocal
set "PYTHONPATH=$Lib;%PYTHONPATH%"
"$python" -m warpep %*
"@ | Set-Content -Path (Join-Path $Bin "warpep.cmd") -Encoding ASCII

    @"
`$env:PYTHONPATH = "$Lib" + `$(if (`$env:PYTHONPATH) { ";" + `$env:PYTHONPATH } else { "" })
& "$python" -m warpep @args
"@ | Set-Content -Path (Join-Path $Bin "warpep.ps1") -Encoding UTF8

    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$Bin*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$userPath;$Bin", "User")
        Warn "added $Bin to your PATH: open a NEW terminal for the 'warpep' command to appear"
    }
    $env:Path = "$env:Path;$Bin"

    Good "installed to $Bin\warpep.cmd"

    Say "verifying the install"
    $env:PYTHONPATH = $Lib
    & $python -m warpep selftest | Out-Null
    if ($LASTEXITCODE -eq 0) { Good "selftest passed: crypto vectors and scan loop are healthy" }
    else { Warn "selftest reported problems, run: warpep selftest" }

    Write-Host ""
    Write-Host "  quick start" -ForegroundColor White
    Write-Host "    warpep                      scan and rank WARP endpoints"
    Write-Host "    warpep scan --fast          quick scan"
    Write-Host "    warpep scan --deep          sweep every published prefix and port"
    Write-Host "    warpep verify IP:PORT       prove an endpoint really carries traffic"
    Write-Host "    warpep config -o warp.conf  WireGuard config for the winner"
    Write-Host ""

    if ($Run -or $Fast) {
        Say "starting a real WARP endpoint scan"
        if ($Fast) { & $python -m warpep scan --fast } else { & $python -m warpep scan }
    }
} finally {
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
