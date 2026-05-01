<#
.SYNOPSIS
  Publishes SecAudit.exe (WPF GUI) as a single-file self-contained Windows binary.

.DESCRIPTION
  Produces ONE portable .exe in out\app\ that runs on Win10 22H2 / Win11 without
  requiring .NET 8 runtime to be installed. Prompts UAC on launch (admin manifest
  baked in via app.manifest). This WPF GUI is not a WinPE target; use
  publish-cli.ps1 for the WinPE/offline boot USB executable.

  Key publish settings and why:
    SelfContained=true                    : target machines may not have .NET 8.
    PublishSingleFile=true                : SOC operator copies one file via USB.
    RuntimeIdentifier=win-x64             : Win10/11 desktops are x64.
    InvariantGlobalization=false          : MUST stay false — vi-VN locale,
                                            DateTime/Number formatting, and WPF
                                            text rendering all depend on ICU.
                                            (Different from CLI which targets
                                            stripped-down WinPE.)
    PublishTrimmed=false                  : WPF XAML, System.Management/WMI, and
                                            DI reflection break under trimming.
    PublishReadyToRun=true                : WPF cold-start matters for desktop UX
                                            (~700 ms saved). Worth the +60 MB.
    IncludeAllContentForSelfExtract=true  : embedded SQLite/JSON assets live next
                                            to native libs in extract dir.
    EnableCompressionInSingleFile=true    : shrinks the exe ~35-40%.
    SatelliteResourceLanguages=en-US;vi-VN: only ship the two UI cultures we use,
                                            avoid the full satellite tree.

.PARAMETER Configuration
  Build configuration (default: Release).

.PARAMETER OutputDir
  Where to write SecAudit.exe. Default: <repo>\out\app

.PARAMETER SkipSmokeTest
  Skip the host smoke test (the GUI exe cannot be probed with --help — we just
  check the file size + native PE header).

.EXAMPLE
  ./build/publish-app.ps1
  Produces out\app\SecAudit.exe in Release mode.
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string]$Configuration = 'Release',

    [string]$OutputDir,

    [switch]$SkipSmokeTest
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot  = Split-Path -Parent $scriptDir
$project   = Join-Path $repoRoot 'src\SecAudit.App\SecAudit.App.csproj'

if (-not $OutputDir) { $OutputDir = Join-Path $repoRoot 'out\app' }

if (-not (Test-Path $project)) {
    throw "Project not found: $project"
}

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " SecAudit.App (GUI) - publish single-file self-contained"     -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " Repo    : $repoRoot"
Write-Host " Project : $project"
Write-Host " Config  : $Configuration"
Write-Host " Output  : $OutputDir"
Write-Host ""

# 1. Clean previous output - single-file publish is sensitive to stale native libs.
if (Test-Path $OutputDir) {
    Write-Host "[1/5] Cleaning $OutputDir ..." -ForegroundColor DarkGray
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# 2. Publish.
Write-Host "[2/5] dotnet publish ..." -ForegroundColor DarkGray
$publishArgs = @(
    'publish', $project,
    '-c', $Configuration,
    '-r', 'win-x64',
    '-o', $OutputDir,
    '-m:1',
    '--nologo',
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:IncludeAllContentForSelfExtract=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:PublishTrimmed=false',
    '-p:PublishReadyToRun=true',
    '-p:DebugType=embedded',
    '-p:SatelliteResourceLanguages=en-US%3Bvi-VN'
)
& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$exePath = Join-Path $OutputDir 'SecAudit.exe'
if (-not (Test-Path $exePath)) {
    throw "Publish succeeded but SecAudit.exe was not produced at $exePath"
}

# 3. Verify single-file layout: .exe + .pdb only. appsettings.json is allowed
#    because it ships next to the exe so an admin can edit logging level without
#    rebuilding.
Write-Host "[3/5] Verifying single-file layout ..." -ForegroundColor DarkGray
$stray = Get-ChildItem $OutputDir -File | Where-Object {
    $_.Name -notmatch '^SecAudit\.(exe|pdb)$' -and $_.Name -ne 'appsettings.json'
}
if ($stray.Count -gt 0) {
    Write-Warning "Single-file output contains extra files (would clutter portable deploy):"
    $stray | ForEach-Object { Write-Warning "  $($_.Name)" }
}

# 4. Report size + SHA-256 for provenance.
Write-Host "[4/5] Computing checksum ..." -ForegroundColor DarkGray
$exe   = Get-Item $exePath
$sizeM = [Math]::Round($exe.Length / 1MB, 1)
$hash  = (Get-FileHash $exePath -Algorithm SHA256).Hash

Write-Host ""
Write-Host "  File  : $($exe.FullName)"
Write-Host "  Size  : $sizeM MB"
Write-Host "  SHA256: $hash"
Write-Host ""

if ($sizeM -gt 400) {
    Write-Warning "Single-file exe is $sizeM MB - larger than expected (<400 MB target)."
}

# 5. Smoke test: a WPF GUI cannot be probed with --help (it would pop a window).
#    Just verify it is a valid PE32+ binary by reading the DOS/PE headers.
if (-not $SkipSmokeTest) {
    Write-Host "[5/5] Verifying PE header ..." -ForegroundColor DarkGray
    $bytes = [System.IO.File]::ReadAllBytes($exePath)
    if ($bytes.Length -lt 4096 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "Smoke test failed: $exePath is not a valid PE binary (no MZ header)."
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) {
        throw "Smoke test failed: $exePath has no PE signature."
    }
    Write-Host "       OK (valid PE32+ binary, $sizeM MB)" -ForegroundColor Green
} else {
    Write-Host "[5/5] Smoke test skipped (-SkipSmokeTest)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "DONE." -ForegroundColor Green
Write-Host "Next: copy SecAudit.exe to the target Win10/11 machine, double-click," -ForegroundColor Green
Write-Host "      accept UAC prompt, app launches in vi-VN by default." -ForegroundColor Green
Write-Host "      For WinPE, publish and run SecAudit.Cli.exe instead." -ForegroundColor Green
