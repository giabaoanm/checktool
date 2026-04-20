using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1562.001 — Impair Defenses: Disable or Modify Tools.
///
/// Trước khi chạy payload, attacker hay tắt Defender / AMSI / EDR. Rule này bắt
/// hai pattern:
/// <list type="bullet">
/// <item>Sysmon Event 1 — command line có các chuỗi tắt Defender
/// (<c>Set-MpPreference -DisableRealtimeMonitoring</c>, <c>sc stop WinDefend</c>,
/// <c>bcdedit /set {default} safeboot</c>, <c>mpcmdrun.exe -RemoveDefinitions -All</c>).</item>
/// <item>Sysmon Event 13 — registry set vào các key vô hiệu hoá Defender
/// (<c>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware</c>,
/// <c>...\\Real-Time Protection\\DisableRealtimeMonitoring</c>).</item>
/// </list>
/// </summary>
public sealed class DefenderTamperingRule : IDetectionRule
{
    public string Id => "SYSMON-DEFENDER-OFF";
    public string Name => "Tắt/cản trở Defender/EDR (Impair Defenses)";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Substring cờ đỏ trong CommandLine. Match case-insensitive.
    /// </summary>
    private static readonly string[] CommandLineMarkers =
    {
        "set-mppreference -disablerealtimemonitoring",
        "set-mppreference -disableioavprotection",
        "set-mppreference -disablebehaviormonitoring",
        "set-mppreference -disableblockatfirstseen",
        "set-mppreference -disablescriptscanning",
        "set-mppreference -submitsamplesconsent 0",
        "add-mppreference -exclusionpath",
        "add-mppreference -exclusionprocess",
        "add-mppreference -exclusionextension",
        "mpcmdrun.exe -removedefinitions -all",
        "mpcmdrun -removedefinitions",
        "sc stop windefend", "sc.exe stop windefend",
        "sc stop sense", "sc.exe stop sense",      // Defender ATP
        "sc stop mpssvc", "sc.exe stop mpssvc",    // Firewall
        "net stop windefend", "net stop mpssvc",
        "bcdedit /set {default} safeboot",
        "bcdedit /set safeboot minimal",
        "wevtutil cl security", "wevtutil cl system",
        "wevtutil cl microsoft-windows-sysmon/operational",
        "fltmc unload",                              // unload AV minifilter
        "reg add hklm\\software\\policies\\microsoft\\windows defender"
    };

    /// <summary>
    /// Registry path cờ đỏ cho Event 13. Match theo prefix case-insensitive.
    /// </summary>
    private static readonly string[] RegistryMarkers =
    {
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus",
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        @"HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware",
        @"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend\Start",
        @"HKLM\SYSTEM\CurrentControlSet\Services\Sense\Start",
        @"HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc\Start",
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Exploit Guard",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        @"HKLM\SOFTWARE\Microsoft\AMSI\Providers"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 1 (CommandLine) + Event 13 (RegistryValueSet)",
        "MITRE ATT&CK T1562.001 — Impair Defenses",
        "Sigma: proc_creation_win_powershell_amsi_bypass.yml"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind == "sysmon.process")
        {
            var commandLine = (record.GetField("CommandLine") ?? string.Empty).ToLowerInvariant();
            if (commandLine.Length == 0) { return; }

            string? matched = null;
            foreach (var m in CommandLineMarkers)
            {
                if (commandLine.Contains(m, StringComparison.Ordinal)) { matched = m; break; }
            }
            if (matched is null) { return; }

            var image = record.GetField("Image") ?? string.Empty;
            var imageName = SysmonHelpers.GetFileName(image);
            var key = "cmd|" + imageName + "|" + matched;
            if (!_emitted.Add(key)) { return; }

            EmitFinding(ctx, record, "CommandLine", matched, image, commandLine);
        }
        else if (record.EventKind == "sysmon.regset")
        {
            var target = record.GetField("TargetObject") ?? string.Empty;
            if (target.Length == 0) { return; }

            string? matched = null;
            foreach (var m in RegistryMarkers)
            {
                if (target.StartsWith(m, StringComparison.OrdinalIgnoreCase))
                {
                    matched = m;
                    break;
                }
            }
            if (matched is null) { return; }

            var image = record.GetField("Image") ?? string.Empty;
            var details = record.GetField("Details") ?? string.Empty;
            var key = "reg|" + target + "|" + details;
            if (!_emitted.Add(key)) { return; }

            EmitFinding(ctx, record, "Registry", matched,
                image, $"Target={target}  NewValue={details}");
        }
    }

    private static void EmitFinding(ForensicsContext ctx, LogRecord record, string source,
        string matched, string image, string detail)
    {
        var preview = detail.Length > 300 ? detail[..300] + "…" : detail;
        var user = record.GetField("User") ?? "(unknown)";

        ctx.Emit(Finding.Create(
            id: $"SYSMON-DEFENDER-OFF-{SysmonHelpers.StableHash(source + matched + preview)}",
            title: $"Thao tác vô hiệu hoá Defender/EDR qua {source}",
            severity: Severity.Critical,
            category: "log-forensics.defense-evasion",
            asset: $"host:{ctx.MachineName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"Signal source: {source}\nUser: {user}\nImage: {image}\n"
                + $"Marker trúng: \"{matched}\"\nDetail: {preview}",
            remediation:
                "Bật lại Defender ngay (Set-MpPreference -DisableRealtimeMonitoring $false). "
                + "Kiểm tra tamper protection đã bật chưa (HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection=5). "
                + "Truy quét full với MpCmdRun -Scan -ScanType 2. Vì attacker đã chủ động tắt AV, "
                + "có khả năng cao host đã bị infection — cân nhắc reimage thay vì chỉ khôi phục.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
