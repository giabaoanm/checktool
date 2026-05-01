<#
.SYNOPSIS
  Publishes SecAudit.Cli.exe as a single-file self-contained binary suitable for WinPE.

.DESCRIPTION
  Produces ONE .exe file in out\cli\ that can be copied to a WinPE boot USB and run
  without any .NET runtime installed on the target. Designed for the IR scenario where
  the operator boots a victim machine from Hiren's BootCD PE / Gandalf's Win10 PE /
  a stock ADK WinPE image, mounts the internal disk, and runs:

      D:\> SecAudit.Cli.exe scan --offline C:\ --malware-path C:\Users\Public\suspect --output X:\report --formats json,html

  Key publish settings and why:
    SelfContained=true                    : WinPE has no .NET runtime.
    PublishSingleFile=true                : operator copies ONE file over USB.
    RuntimeIdentifier=win-x64             : WinPE x64 is the supported target.
    InvariantGlobalization=true           : stock WinPE lacks icu.dll so culture APIs
                                            crash on startup. Forces invariant locale.
    PublishTrimmed=false                  : System.Management / WMI uses reflection on
                                            types the trimmer cannot see. Trimming
                                            guarantees runtime breakage.
    PublishReadyToRun=false               : CLI cold-start is rare (one-shot tool).
                                            R2R adds ~80 MB of precompiled code for a
                                            latency win we do not need.
    IncludeAllContentForSelfExtract=true  : embedded SQLite / JSON assets live next to
                                            the native libs in the extract dir so WMI
                                            and CVE-pipeline can find them.
    EnableCompressionInSingleFile=true    : shrinks the exe ~40%. The cold-start cost
                                            (one-time extract to %TEMP%\.net\...) is
                                            acceptable for a CLI.

.PARAMETER Configuration
  Build configuration (default: Release). Use Debug only when investigating publish issues.

.PARAMETER OutputDir
  Where to write SecAudit.Cli.exe. Default: <repo>\out\cli for win-x64,
  or <repo>\out\cli-x86 for win-x86.

.PARAMETER RuntimeIdentifier
  Runtime to publish. win-x64 targets normal x64 WinPE. win-x86 targets older
  32-bit WinPE images such as NHV-10PE32.

.PARAMETER WinPeUsb
  Optional. If set (or if $env:WINPE_USB is set), the published exe is also copied there
  so you do not have to chase the output path manually.

.PARAMETER SkipSmokeTest
  Skip the PE-header smoke test. The script verifies the generated PE header by
  default; full scan execution is left to an elevated/live or WinPE context.

.EXAMPLE
  ./build/publish-cli.ps1
  Produces out\cli\SecAudit.Cli.exe in Release mode.

.EXAMPLE
  $env:WINPE_USB = 'E:\SecAudit\'; ./build/publish-cli.ps1
  Publishes and copies to a mounted WinPE USB drive in one step.
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string]$Configuration = 'Release',

    [string]$OutputDir,

    [ValidateSet('win-x64','win-x86')]
    [string]$RuntimeIdentifier = 'win-x64',

    [string]$WinPeUsb,

    [switch]$SkipSmokeTest
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot  = Split-Path -Parent $scriptDir
$project   = Join-Path $repoRoot 'src\SecAudit.Cli\SecAudit.Cli.csproj'

if (-not $OutputDir) {
    $OutputDir = Join-Path $repoRoot ($(if ($RuntimeIdentifier -eq 'win-x86') { 'out\cli-x86' } else { 'out\cli' }))
}
$platformTarget = if ($RuntimeIdentifier -eq 'win-x86') { 'x86' } else { 'x64' }

# Resolve USB target: CLI param wins, else env var, else null
if (-not $WinPeUsb -and $env:WINPE_USB) { $WinPeUsb = $env:WINPE_USB }

if (-not (Test-Path $project)) {
    throw "Project not found: $project"
}

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " SecAudit.Cli - publish single-file self-contained (WinPE)"   -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " Repo    : $repoRoot"
Write-Host " Project : $project"
Write-Host " Config  : $Configuration"
Write-Host " RID     : $RuntimeIdentifier"
Write-Host " Output  : $OutputDir"
if ($WinPeUsb) { Write-Host " USB     : $WinPeUsb" -ForegroundColor Yellow }
Write-Host ""

# 1. Clean previous executable artifacts only. Do not remove the whole folder:
#    operators often run the WinPE launcher from this directory, which writes reports
#    into out\cli\reports or sometimes directly into out\cli. Removing the directory
#    can delete evidence or fail when a PDF report is open.
if (Test-Path $OutputDir) {
    Write-Host "[1/6] Cleaning previous CLI binaries in $OutputDir ..." -ForegroundColor DarkGray
    foreach ($name in @('SecAudit.Cli.exe', 'SecAudit.Cli.pdb', 'Run-SecAudit-WinPE.cmd')) {
        $path = Join-Path $OutputDir $name
        if (Test-Path $path) {
            Remove-Item -Force -LiteralPath $path
        }
    }
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# 2. Clean the project graph before switching x64/x86. MSBuild class-library
#    outputs do not include the RID in their default path, so publishing win-x86
#    followed by win-x64 can otherwise leave stale processor-specific references.
Write-Host "[2/6] dotnet clean ..." -ForegroundColor DarkGray
$cleanArgs = @(
    'clean', $project,
    '-c', $Configuration,
    '-m:1',
    '--nologo'
)
& dotnet @cleanArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet clean failed with exit code $LASTEXITCODE"
}

# 3. Publish with all the WinPE-compatibility flags.
Write-Host "[3/6] dotnet publish ..." -ForegroundColor DarkGray
$publishArgs = @(
    'publish', $project,
    '-c', $Configuration,
    '-r', $RuntimeIdentifier,
    '-o', $OutputDir,
    '-m:1',
    '--nologo',
    '--self-contained', 'true',
    "-p:PlatformTarget=$platformTarget",
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:IncludeAllContentForSelfExtract=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:InvariantGlobalization=true',
    '-p:PublishTrimmed=false',
    '-p:PublishReadyToRun=false',
    '-p:DebugType=embedded',
    '-p:SatelliteResourceLanguages=en-US%3Bvi-VN'
)
& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$exePath = Join-Path $OutputDir 'SecAudit.Cli.exe'
if (-not (Test-Path $exePath)) {
    throw "Publish succeeded but SecAudit.Cli.exe was not produced at $exePath"
}

# 4. Verify it is actually single-file: nothing but .exe + .pdb should remain.
Write-Host "[4/6] Verifying single-file layout ..." -ForegroundColor DarkGray
$stray = Get-ChildItem $OutputDir -File | Where-Object {
    $_.Name -notmatch '^SecAudit\.Cli\.(exe|pdb)$' `
        -and $_.Name -notmatch '^secaudit-.*\.(html|pdf|json|docx|csv|txt)$'
}
if ($stray.Count -gt 0) {
    Write-Warning "Output contains extra non-report files:"
    $stray | ForEach-Object { Write-Warning "  $($_.Name)" }
    Write-Warning "Check for projects that set CopyToPublishDirectory=Always on loose DLLs."
}

# 5. Report size + SHA-256 for provenance.
Write-Host "[5/6] Computing checksum ..." -ForegroundColor DarkGray
$exe   = Get-Item $exePath
$sizeM = [Math]::Round($exe.Length / 1MB, 1)
$hash  = (Get-FileHash $exePath -Algorithm SHA256).Hash

Write-Host ""
Write-Host "  File  : $($exe.FullName)"
Write-Host "  Size  : $sizeM MB"
Write-Host "  SHA256: $hash"
Write-Host ""

if ($sizeM -gt 200) {
    Write-Warning "Single-file exe is $sizeM MB - larger than expected (~80-140 MB). "
    Write-Warning "Check that PublishReadyToRun is OFF for CLI and PublishTrimmed stays OFF."
}

# 6. Smoke-test: verify it is a valid console PE binary with the requested architecture.
#    Full scan execution is intentionally left to an elevated/live or WinPE context.
if (-not $SkipSmokeTest) {
    Write-Host "[6/6] Verifying PE header ..." -ForegroundColor DarkGray
    $bytes = [System.IO.File]::ReadAllBytes($exePath)
    if ($bytes.Length -lt 4096 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "Smoke test failed: $exePath is not a valid PE binary (no MZ header)."
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) {
        throw "Smoke test failed: $exePath has no PE signature."
    }
    $subsystem = [BitConverter]::ToUInt16($bytes, $peOffset + 24 + 68)
    if ($subsystem -ne 3) {
        throw "Smoke test failed: $exePath is not a console subsystem binary (subsystem=$subsystem)."
    }
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $magic = [BitConverter]::ToUInt16($bytes, $peOffset + 0x18)
    $peKind = if ($magic -eq 0x020B) { 'PE32+' } elseif ($magic -eq 0x010B) { 'PE32' } else { ('PE magic 0x{0:X4}' -f $magic) }
    $expectedMachine = if ($RuntimeIdentifier -eq 'win-x86') { 0x014C } else { 0x8664 }
    if ($machine -ne $expectedMachine) {
        throw ("Smoke test failed: $exePath machine type 0x{0:X4} does not match $RuntimeIdentifier." -f $machine)
    }
    Write-Host "       OK (valid $peKind console binary, $sizeM MB)" -ForegroundColor Green
} else {
    Write-Host "[6/6] Smoke test skipped (-SkipSmokeTest)" -ForegroundColor DarkGray
}

# 6. WinPE launcher: double-click friendly, keeps .NET single-file extraction
#    cache on the USB drive instead of a tiny X:\ RAM-disk TEMP folder.
$launcherPath = Join-Path $OutputDir 'Run-SecAudit-WinPE.cmd'
@'
@echo off
setlocal
cd /d "%~dp0"

if not exist "%~dp0reports" mkdir "%~dp0reports"
if not exist "%~dp0.secaudit-cache" mkdir "%~dp0.secaudit-cache"
if not exist "%~dp0.secaudit-temp" mkdir "%~dp0.secaudit-temp"

set "DOTNET_BUNDLE_EXTRACT_BASE_DIR=%~dp0.secaudit-cache"
set "TEMP=%~dp0.secaudit-temp"
set "TMP=%~dp0.secaudit-temp"

echo SecAudit WinPE offline scan
echo Reports: %~dp0reports
echo.
echo Extra arguments passed to this script are forwarded to SecAudit.Cli.exe.
echo Example: Run-SecAudit-WinPE.cmd --malware-path D:\Users\Public\suspect
echo.

"%~dp0SecAudit.Cli.exe" scan --offline auto --output "%~dp0reports" --formats html,json,docx,pdf %*
set "EXITCODE=%ERRORLEVEL%"
echo.
echo SecAudit exit code: %EXITCODE%
pause
exit /b %EXITCODE%
'@ | Set-Content -LiteralPath $launcherPath -Encoding ASCII
Write-Host "WinPE launcher: $launcherPath" -ForegroundColor Green

# 7. Optional: copy to USB.
if ($WinPeUsb) {
    if (-not (Test-Path $WinPeUsb)) {
        Write-Warning "WinPE USB path '$WinPeUsb' does not exist - skipping copy."
    } else {
        Copy-Item $exePath -Destination $WinPeUsb -Force
        Copy-Item $launcherPath -Destination $WinPeUsb -Force
        $usbExe = Join-Path $WinPeUsb 'SecAudit.Cli.exe'
        Write-Host "Copied to WinPE USB: $usbExe" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "DONE." -ForegroundColor Green
Write-Host "Next: copy the exe to a WinPE boot USB, boot target machine, run:" -ForegroundColor Green
Write-Host '      SecAudit.Cli.exe scan --offline C:\ --malware-path C:\Users\Public\suspect --output X:\report --formats json,html' -ForegroundColor Green
