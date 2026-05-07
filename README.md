# SecAudit

[![CI](https://github.com/giabaoanm/checktool/actions/workflows/ci.yml/badge.svg)](https://github.com/giabaoanm/checktool/actions/workflows/ci.yml)
[![CodeQL](https://github.com/giabaoanm/checktool/actions/workflows/codeql.yml/badge.svg)](https://github.com/giabaoanm/checktool/actions/workflows/codeql.yml)

Professional Windows 10/11 security audit suite for IT admins and SOC analysts.

**Status:** Active Windows prototype. The WPF shell, CLI runner, core audit modules,
offline WinPE path, reporting, and focused regression tests are present. Some deep
checks remain roadmap items; see "Known gaps" below.

## Modules

1. **System Info & License Audit** - hardware, OS, Windows/Office activation, KMSpico/KMSAuto heuristics, installed software inventory.
2. **Hardening Audit** - CIS-style checks for Defender, Firewall, BitLocker, UAC, SMBv1, RDP NLA, Credential Guard, PowerShell logging, risky firewall rules, and related settings.
3. **Patch / CVE Audit** - installed KB inventory plus fast-path rules for high-impact Windows CVEs; NVD DB freshness is tracked.
4. **LAN Scanner /24** - local subnet discovery, host sweep, TCP port scan, SMBv1 and RDP-NLA probes.
5. **Remote Access & Persistence** - installed remote-access tools, Run keys, services, scheduled tasks, WMI subscriptions, IFEO and Winlogon hijack checks.
6. **Log Forensics** - Windows XML/EVTX, Linux auth/syslog, web access/error logs, Bash history, Sysmon rules, and kill-chain correlation.
7. **Malware Inspector / IOC Export** - static PE triage, local offline reputation, cracker-family signatures, Authenticode checks, Prefetch/AmCache/system persistence, and IOC exports for AV hand-off.
8. **Device & Network Forensics** - USB/MTP history, Wi-Fi/network profiles, IP configuration, live egress, and SRUM egress history.
9. **Reporting** - HTML, PDF, JSON, and DOCX reports with formal report metadata.

## Build

Requires .NET 8 SDK (8.0.400+) on Windows 10/11.

```powershell
dotnet restore
dotnet build -c Release
dotnet test -c Debug --no-restore
```

Run the WPF shell:

```powershell
dotnet run --project src/SecAudit.App
```

Single-file portable publish:

```powershell
pwsh build/publish-app.ps1
pwsh build/publish-cli.ps1
```

SecAudit ships as two runnable files:

- `SecAudit.exe` - WPF GUI for normal Windows 10/11 sessions.
- `SecAudit.Cli.exe` - WinPE/offline runner for boot USB and recovery scenarios.

## Offline Malware Triage

MalwareInspector is designed for isolated LAN and WinPE use. It does not upload samples
or call a cloud API; it hashes candidate files, evaluates local static rules, checks
the internal YARA-compatible rule pack, checks an optional local reputation feed, and
writes IOC files for AV hand-off.

```powershell
SecAudit.Cli.exe scan --offline D:\ --malware-path D:\Users\Public\suspect --output F:\reports
SecAudit.Cli.exe scan --malware-path C:\Temp\suspicious.exe --formats html,json
```

The GUI has a **Quét mã độc** page for the same workflow on a normal Windows session:
choose a suspicious file/folder, run offline triage, review reputation/YARA hits, then
export IOC files.

Place a local hash feed at `%ProgramData%\SecAudit\signatures\local-reputation.json`
or beside the published executable under `signatures\local-reputation.json`:

```json
{
  "hashes": [
    {
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "verdict": "Malicious",
      "family": "Trojan.Example",
      "confidence": 100,
      "source": "LocalSOC"
    }
  ]
}
```

The CSV IOC export includes `ReputationVerdict`, `ReputationFamily`,
`ReputationConfidence`, and `ReputationReason` so analysts can sort the result like a
small offline VirusTotal-style table.

Internal YARA rules:

- Built-in pack: credential dumper, RAT/stealer, ransomware, downloader/LOLBin,
  injection, miner, and EICAR test markers.
- Custom local rules: put `.yar` or `.yara` files in
  `%ProgramData%\SecAudit\signatures\yara` or `signatures\yara` beside the executable.
- Supported subset: string/hex patterns plus simple conditions: `any of them`,
  `all of them`, `N of them`, `$a and $b`, `$a or $b`. This avoids native libyara so
  the same engine remains portable for offline/WinPE CLI use.

## Known Gaps

- Patch/CVE currently relies on fast-path KB rules; full NVD version-range matching for third-party software is not complete.
- Offline mode intentionally runs only Patch/CVE, RemoteAccess, LogForensics, and MalwareInspector; HKCU NTUSER.DAT, offline WMI repository parsing, BitLocker runtime state, and deep file-version CVE checks remain roadmap items.
- The credential extraction module from the original plan is not implemented and should stay out of scope unless there is a strict legal/authorization workflow.
- Documentation screenshots referenced by `docs/user-guide.md` are not committed yet.

## Authorized Use Only

This tool performs system audits, network scans, and forensic collection that may be
illegal without explicit authorization. See [EULA](EULA.md).
