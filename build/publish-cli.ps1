<#
.SYNOPSIS
  Publishes SecAudit.Cli.exe as a single-file self-contained binary suitable for WinPE.

.DESCRIPTION
  Produces ONE .exe file in out\cli\ that can be copied to a WinPE boot USB and run
  without any .NET runtime installed on the target. Designed for the IR scenario where
  the operator boots a victim machine from Hiren's BootCD PE / Gandalf's Win10 PE /
  a stock ADK WinPE image, mounts the internal disk, and runs:

      D:\> SecAudit.Cli.exe --offline C:\ --output X:\report --formats json,html

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
  Where to write SecAudit.Cli.exe. Default: <repo>\out\cli

.PARAMETER WinPeUsb
  Optional. If set (or if $env:WINPE_USB is set), the published exe is also copied there
  so you do not have to chase the output path manually.

.PARAMETER SkipSmokeTest
  Skip the --help smoke test that runs the just-published exe on the host machine.
  Use when running under a non-Windows build agent or in an isolated sandbox.

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

    [string]$WinPeUsb,

    [switch]$SkipSmokeTest
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot  = Split-Path -Parent $scriptDir
$project   = Join-Path $repoRoot 'src\SecAudit.Cli\SecAudit.Cli.csproj'

if (-not $OutputDir) { $OutputDir = Join-Path $repoRoot 'out\cli' }

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
Write-Host " Output  : $OutputDir"
if ($WinPeUsb) { Write-Host " USB     : $WinPeUsb" -ForegroundColor Yellow }
Write-Host ""

# 1. Clean previous output - single-file publish is sensitive to stale native libs.
if (Test-Path $OutputDir) {
    Write-Host "[1/5] Cleaning $OutputDir ..." -ForegroundColor DarkGray
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# 2. Publish with all the WinPE-compatibility flags.
Write-Host "[2/5] dotnet publish ..." -ForegroundColor DarkGray
$publishArgs = @(
    'publish', $project,
    '-c', $Configuration,
    '-r', 'win-x64',
    '-o', $OutputDir,
    '--nologo',
    '--self-contained', 'true',
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

# 3. Verify it is actually single-file: nothing but .exe + .pdb should remain.
Write-Host "[3/5] Verifying single-file layout ..." -ForegroundColor DarkGray
$stray = Get-ChildItem $OutputDir -File | Where-Object {
    $_.Name -notmatch '^SecAudit\.Cli\.(exe|pdb)$'
}
if ($stray.Count -gt 0) {
    Write-Warning "Single-file output contains extra files (would break WinPE deploy):"
    $stray | ForEach-Object { Write-Warning "  $($_.Name)" }
    Write-Warning "Check for projects that set CopyToPublishDirectory=Always on loose DLLs."
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

if ($sizeM -gt 200) {
    Write-Warning "Single-file exe is $sizeM MB - larger than expected (~80-140 MB). "
    Write-Warning "Check that PublishReadyToRun is OFF for CLI and PublishTrimmed stays OFF."
}

# 5. Smoke-test on the host: exe must at least print --help without throwing.
if (-not $SkipSmokeTest) {
    Write-Host "[5/5] Smoke test: $exePath --help" -ForegroundColor DarkGray
    $smokeOut = & $exePath --help 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error ("Smoke test failed (exit {0}):`n{1}" -f $LASTEXITCODE, ($smokeOut -join "`n"))
        throw "publish-cli.ps1 smoke test failed"
    }
    $smokeStr = $smokeOut -join "`n"
    if (-not ($smokeStr -match 'SecAudit\.Cli')) {
        Write-Warning "Smoke test: exe ran but --help output did not contain 'SecAudit.Cli' - check for corruption."
    } else {
        Write-Host "       OK (exit 0, help text rendered)" -ForegroundColor Green
    }
} else {
    Write-Host "[5/5] Smoke test skipped (-SkipSmokeTest)" -ForegroundColor DarkGray
}

# 6. Optional: copy to USB.
if ($WinPeUsb) {
    if (-not (Test-Path $WinPeUsb)) {
        Write-Warning "WinPE USB path '$WinPeUsb' does not exist - skipping copy."
    } else {
        Copy-Item $exePath -Destination $WinPeUsb -Force
        $usbExe = Join-Path $WinPeUsb 'SecAudit.Cli.exe'
        Write-Host "Copied to WinPE USB: $usbExe" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "DONE." -ForegroundColor Green
Write-Host "Next: copy the exe to a WinPE boot USB, boot target machine, run:" -ForegroundColor Green
Write-Host '      SecAudit.Cli.exe --offline C:\ --output X:\report --formats json,html' -ForegroundColor Green
