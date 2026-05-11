using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects the SECOND-ORDER preparation activity ransomware does in the 30-90
/// seconds before the actual encryption sweep. Complements
/// <see cref="RansomwareRule"/> (which catches the encryption itself + classic
/// VSS deletion) by adding markers SOC-grade rules typically watch for:
///
/// <list type="bullet">
///   <item><b>Recovery sabotage beyond VSS</b> — <c>bcdedit /deletevalue</c>,
///         <c>bcdedit /set safeboot minimal</c>, <c>fsutil quota disable</c>,
///         <c>fsutil resource setautoreset</c>, <c>wbadmin delete backup</c>.</item>
///   <item><b>AV/EDR tampering</b> — <c>Add-MpPreference -ExclusionPath</c> /
///         <c>-ExclusionExtension</c>, <c>Set-MpPreference -DisableRealtimeMonitoring $true</c>,
///         <c>taskkill /F /IM MsMpEng.exe</c>, <c>net stop WinDefend</c>.</item>
///   <item><b>Critical-service stop</b> — <c>net stop</c> / <c>sc stop</c>
///         targeting backup/SQL/Exchange services so files unlock before
///         encryption (<c>VeeamBackupSvc</c>, <c>MSSQLSERVER</c>,
///         <c>MSExchangeIS</c>, <c>SQLWriter</c>, etc.).</item>
///   <item><b>Recycle bin + event log clear</b> — <c>Clear-RecycleBin -Force</c>,
///         <c>wevtutil cl Security /q:true</c> (Critical because attacker is
///         removing forensic trail).</item>
/// </list>
/// </summary>
public sealed class RansomwarePrecursorRule : IDetectionRule
{
    public string Id => "FOR-RANSOM-PRE";
    public string Name => "Ransomware precursor (recovery sabotage / AV tamper / service stop)";

    private static readonly string[] RecoverySabotageRefs =
    {
        "MITRE ATT&CK T1490 — Inhibit System Recovery",
        "MITRE ATT&CK T1486 — Data Encrypted for Impact"
    };
    private static readonly string[] AvTamperRefs =
    {
        "MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools",
        "MITRE ATT&CK T1562.004 — Disable or Modify System Firewall"
    };
    private static readonly string[] ServiceStopRefs =
    {
        "MITRE ATT&CK T1489 — Service Stop",
        "MITRE ATT&CK T1486 — Data Encrypted for Impact"
    };
    private static readonly string[] EvidenceRemovalRefs =
    {
        "MITRE ATT&CK T1070.001 — Indicator Removal: Clear Windows Event Logs",
        "MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion"
    };

    private static readonly (string Marker, string Category, Severity Sev, string[] Refs)[] Patterns = new (string, string, Severity, string[])[]
    {
        // --- Recovery sabotage beyond classic VSS ---
        ("bcdedit /set safeboot",       "boot-tampering",      Severity.High,     RecoverySabotageRefs),
        ("bcdedit /set {default} safeboot", "boot-tampering",   Severity.High,     RecoverySabotageRefs),
        ("bcdedit /deletevalue",        "boot-tampering",      Severity.High,     RecoverySabotageRefs),
        ("fsutil quota disable",        "quota-tamper",        Severity.High,     RecoverySabotageRefs),
        ("fsutil resource setautoreset", "txn-tamper",         Severity.High,     RecoverySabotageRefs),
        ("wbadmin delete backup",       "backup-deletion",     Severity.Critical, RecoverySabotageRefs),

        // --- AV/EDR tampering ---
        ("add-mppreference -exclusionpath", "defender-bypass", Severity.High,     AvTamperRefs),
        ("add-mppreference -exclusionextension", "defender-bypass", Severity.High, AvTamperRefs),
        ("add-mppreference -exclusionprocess", "defender-bypass", Severity.High,  AvTamperRefs),
        ("set-mppreference -disablerealtimemonitoring", "defender-bypass", Severity.Critical, AvTamperRefs),
        ("set-mppreference -disablebehaviormonitoring", "defender-bypass", Severity.High, AvTamperRefs),
        ("set-mppreference -disablescriptscanning", "defender-bypass", Severity.High, AvTamperRefs),
        ("set-mppreference -mapsreporting 0", "defender-bypass", Severity.Medium, AvTamperRefs),
        ("set-mppreference -submitsamplesconsent 2", "defender-bypass", Severity.Medium, AvTamperRefs),
        ("taskkill /f /im msmpeng",     "defender-kill",       Severity.Critical, AvTamperRefs),
        ("net stop windefend",          "defender-kill",       Severity.Critical, AvTamperRefs),
        ("sc stop windefend",           "defender-kill",       Severity.Critical, AvTamperRefs),
        ("sc config windefend start= disabled", "defender-kill", Severity.Critical, AvTamperRefs),

        // --- Backup / database service stop (so files unlock for encryption) ---
        ("net stop veeam",              "backup-service-stop", Severity.High,     ServiceStopRefs),
        ("net stop bedbg",              "backup-service-stop", Severity.High,     ServiceStopRefs), // BackupExec
        ("net stop msexchange",         "exchange-stop",       Severity.High,     ServiceStopRefs),
        ("net stop mssqlserver",        "sql-stop",            Severity.High,     ServiceStopRefs),
        ("net stop sqlwriter",          "sql-stop",            Severity.High,     ServiceStopRefs),
        ("net stop sqlserveragent",     "sql-stop",            Severity.High,     ServiceStopRefs),
        ("net stop \"acronis",          "backup-service-stop", Severity.High,     ServiceStopRefs),
        ("sc stop veeam",               "backup-service-stop", Severity.High,     ServiceStopRefs),
        ("sc stop mssqlserver",         "sql-stop",            Severity.High,     ServiceStopRefs),
        ("stop-service -name veeam",    "backup-service-stop", Severity.High,     ServiceStopRefs),
        ("stop-service -name mssql",    "sql-stop",            Severity.High,     ServiceStopRefs),

        // --- Forensic trail clearing ---
        ("clear-recyclebin -force",     "evidence-removal",    Severity.High,     EvidenceRemovalRefs),
        ("clear-eventlog",              "evidence-removal",    Severity.Critical, EvidenceRemovalRefs),
        ("wevtutil cl security",        "evidence-removal",    Severity.Critical, EvidenceRemovalRefs),
        ("wevtutil cl system",          "evidence-removal",    Severity.High,     EvidenceRemovalRefs),
        ("wevtutil cl application",     "evidence-removal",    Severity.High,     EvidenceRemovalRefs),
        ("wevtutil cl \"windows powershell\"", "evidence-removal", Severity.Critical, EvidenceRemovalRefs),
        ("wevtutil cl microsoft-windows-powershell", "evidence-removal", Severity.Critical, EvidenceRemovalRefs),
    };

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(ctx);

        // Pull command line from any of the kinds where it appears.
        string cmd = record.EventKind switch
        {
            "process.created"   => record.GetField("CommandLine") ?? record.GetField("NewProcessName") ?? string.Empty,
            "sysmon.process"    => record.GetField("CommandLine") ?? record.GetField("Image") ?? string.Empty,
            "powershell.scriptblock" => record.GetField("ScriptBlockText") ?? string.Empty,
            "bash.command"      => record.GetField("Command") ?? string.Empty,
            "sudo.command"      => record.GetField("Command") ?? string.Empty,
            _ => string.Empty
        };
        if (string.IsNullOrEmpty(cmd)) { return; }

        var lower = cmd.ToLowerInvariant();
        // Collapse extra whitespace so "net  stop  windefend" still matches.
        var normalized = System.Text.RegularExpressions.Regex.Replace(
            lower, @"\s+", " ", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));

        foreach (var (marker, category, sev, refs) in Patterns)
        {
            if (!normalized.Contains(marker, StringComparison.Ordinal)) { continue; }

            // De-dup per (marker, host) so repeated commands don't spam.
            var key = "PRE:" + category + ":" + marker;
            if (!_emitted.Add(key)) { continue; }

            ctx.Emit(Finding.Create(
                id: $"{Id}-{Math.Abs(key.GetHashCode()):X8}",
                title: $"Tiền-mã-hoá ransomware: {DescribeCategory(category)} — \"{Truncate(marker, 60)}\"",
                severity: sev,
                category: "log-forensics.ransom-precursor",
                asset: $"host:{ctx.MachineName}",
                evidence: $"[{record.SourceFile}:{record.SourceOffset}] Command={cmd}\n"
                        + $"Pattern khớp: \"{marker}\"\n"
                        + $"Phân nhóm: {category}\n"
                        + $"Raw: {record.RawLine}",
                remediation: BuildRemediation(category),
                references: refs));
            break; // one finding per command is enough
        }
    }

    public void Flush(ForensicsContext ctx) { }

    public void Reset() => _emitted.Clear();

    private static string DescribeCategory(string c) => c switch
    {
        "boot-tampering"      => "phá cấu hình khởi động (chặn Recovery)",
        "quota-tamper"        => "tắt disk quota",
        "txn-tamper"          => "tắt transactional NTFS auto-reset",
        "backup-deletion"     => "xoá backup hệ thống",
        "defender-bypass"     => "thêm exclusion / tắt Defender feature",
        "defender-kill"       => "kill Microsoft Defender",
        "backup-service-stop" => "dừng dịch vụ backup",
        "exchange-stop"       => "dừng dịch vụ Exchange",
        "sql-stop"            => "dừng dịch vụ SQL Server",
        "evidence-removal"    => "xoá dấu vết (event log / recycle bin)",
        _                     => c
    };

    private static string BuildRemediation(string category) => category switch
    {
        "boot-tampering" =>
            "Khôi phục cấu hình BCD ngay (bcdedit /set {default} recoveryenabled Yes; "
            + "bcdedit /deletevalue {default} safeboot). Đây là mẫu attacker chuẩn bị "
            + "cho mã hoá — kiểm tra ngay file mã hoá trong vòng vài phút sau timestamp này.",
        "backup-deletion" =>
            "Xác minh backup bị xoá có recover được không (Veeam restore point từ kho riêng, "
            + "Azure Backup, immutable storage). Cô lập máy trước khi attacker tiếp tục mã hoá. "
            + "Đây là Critical vì attacker đã chuyển sang pha Impact.",
        "defender-bypass" =>
            "1) Xoá ngay exclusion vừa thêm (Get-MpPreference | Select Exclusion*; "
            + "Remove-MpPreference -ExclusionPath ...). "
            + "2) Bật lại Real-time monitoring. "
            + "3) Kiểm tra account đã thực thi lệnh này — đây là quyền admin, có thể đã bị chiếm.",
        "defender-kill" =>
            "Coi như Defender đã bị tê liệt. Cô lập máy ngay; rebuild từ image sạch là phương án "
            + "an toàn nhất. Trước reboot: thu memory dump để phân tích payload chính.",
        "backup-service-stop" or "sql-stop" or "exchange-stop" =>
            "Dịch vụ này bị stop để file lock được mở, sẵn sàng cho mã hoá. Khởi động lại dịch vụ "
            + "ngay; kiểm tra dữ liệu integrity; quan sát cùng host xem có file mã hoá xuất hiện "
            + "trong 30-90 giây tiếp theo không.",
        "evidence-removal" =>
            "Attacker đang xoá dấu vết. Ngừng máy + thu disk image NGAY (tránh ghi đè). "
            + "Khôi phục Security log từ event-forwarder hoặc SIEM nếu có. "
            + "Báo cáo IR + cơ quan có thẩm quyền (đối với hệ thống thuộc danh mục dữ liệu nhạy cảm).",
        _ => "Cô lập máy, thu thập bằng chứng (memory + disk image), điều tra account đã chạy lệnh."
    };

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
