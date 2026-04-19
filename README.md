# SecAudit

Professional Windows 10/11 security audit suite for IT admins and SOC analysts.

**Status:** Iteration 0 (skeleton). See [plan](C:/Users/Admin/.claude/plans/harmonic-frolicking-sprout.md).

## Modules (planned)

1. **System Info & License Audit** — hardware, OS, Windows/Office activation, KMSpico heuristics, installed software inventory.
2. **Hardening Audit** — CIS-style checks (Defender, Firewall, BitLocker, UAC, SMBv1, RDP NLA, Credential Guard, ...).
3. **Patch / CVE Audit** — installed KBs vs offline NVD database, fast-path rules for critical CVEs.
4. **LAN Scanner /24** — pure managed C# ARP/ICMP/TCP scan, banner grab, SMBv1/RDP-NLA/share probes.
5. **Credential / Habit Audit** — browser saved passwords (Chromium DPAPI + Firefox NSS managed), Wi-Fi keys, weak local account passwords.

## Build

Requires .NET 8 SDK (8.0.400+) on Windows 10/11.

```
dotnet restore
dotnet build -c Release
```

Run the WPF shell:
```
dotnet run --project src/SecAudit.App
```

Single-file portable publish:
```
pwsh build/publish.ps1
```

## Authorized use only

This tool performs system audits, network scans, and credential extraction that may be illegal without explicit authorization. See [EULA](EULA.md). Vietnamese users: tham khảo Luật An ninh mạng 2018 (Điều 8) và BLHS 2015 sửa đổi (Điều 289).
