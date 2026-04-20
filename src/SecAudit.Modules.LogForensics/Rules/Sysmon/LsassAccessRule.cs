using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1003.001 — OS Credential Dumping: LSASS Memory.
///
/// Sysmon Event 10 (ProcessAccess) ghi lại mọi khi một process mở handle tới
/// tiến trình khác. Mimikatz và các tool tương tự (ProcDump, MiniDumpWriteDump,
/// Dumpert) cần mở lsass.exe với quyền <c>PROCESS_VM_READ | PROCESS_QUERY_INFORMATION</c>
/// = <c>0x1010</c> hoặc <c>0x1410</c>. Đây là signature cực ổn định: admin hợp lệ
/// gần như không bao giờ mở lsass với combo quyền này.
///
/// <para>
/// Chúng ta cho phép whitelist các process Microsoft biết trước (Defender, WerFault,
/// csrss) để giảm noise. Mọi process không trong whitelist mà đụng lsass với dangerous
/// mask đều Critical.
/// </para>
/// </summary>
public sealed class LsassAccessRule : IDetectionRule
{
    public string Id => "SYSMON-LSASS";
    public string Name => "Truy cập LSASS đáng ngờ (credential dumping)";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Các GrantedAccess mask "dangerous" mà credential dumper cần. Lấy từ Mimikatz
    /// source + báo cáo của CrowdStrike. Mask đầy đủ (PROCESS_ALL_ACCESS = 0x1F0FFF)
    /// cũng đương nhiên dangerous.
    /// </summary>
    private static readonly string[] DangerousMasks =
    {
        "0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f0fff",
        "0x1f1fff", "0x101010"
    };

    /// <summary>
    /// Process hệ thống được phép truy cập lsass ở mức cao (Defender scan,
    /// WER khi lsass crash, csrss liên lạc qua ALPC). Khớp theo filename thôi —
    /// nếu attacker masquerade bằng cách đặt tên trùng cũng đã là finding khác rồi.
    /// </summary>
    private static readonly HashSet<string> BenignSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "msmpeng.exe", "nissrv.exe", "mssense.exe", "werfault.exe",
        "wercon.exe", "csrss.exe", "services.exe", "wininit.exe",
        "sppsvc.exe", "lsm.exe", "taskhostw.exe",
        "microsoftedgecp.exe", "svchost.exe"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 10 — ProcessAccess",
        "MITRE ATT&CK T1003.001 — OS Credential Dumping: LSASS Memory",
        "Sigma: proc_access_win_lsass_dump.yml"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.processaccess") { return; }

        var target = record.GetField("TargetImage") ?? string.Empty;
        // Chỉ quan tâm target = lsass.exe. Sysmon ghi full path; match hậu tố.
        if (!target.EndsWith("\\lsass.exe", StringComparison.OrdinalIgnoreCase)) { return; }

        var grantedAccess = (record.GetField("GrantedAccess") ?? string.Empty).ToLowerInvariant();
        bool dangerous = false;
        foreach (var m in DangerousMasks)
        {
            if (grantedAccess.Contains(m, StringComparison.Ordinal)) { dangerous = true; break; }
        }
        if (!dangerous) { return; }

        var source = record.GetField("SourceImage") ?? "(unknown)";
        var sourceName = SysmonHelpers.GetFileName(source);
        if (BenignSources.Contains(sourceName)) { return; }

        // Dedup: cùng source process truy cập lsass nhiều lần chỉ emit 1 finding.
        var key = sourceName + "|" + grantedAccess;
        if (!_emitted.Add(key)) { return; }

        var callTrace = record.GetField("CallTrace") ?? "(not captured)";
        var sourceUser = record.GetField("SourceUser") ?? "(unknown)";

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"Tiến trình {sourceName} truy cập bộ nhớ LSASS với quyền nguy hiểm",
            severity: Severity.Critical,
            category: "log-forensics.credential-access",
            asset: $"process:{sourceName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"Source: {source} (user={sourceUser})\n"
                + $"Target: {target}\n"
                + $"GrantedAccess: {grantedAccess} (mask credential-dumping)\n"
                + $"CallTrace: {callTrace}",
            remediation:
                "Xác minh ngay tiến trình nguồn. Nếu không phải Defender / WER / tool hợp lệ: "
                + "cách ly máy, dump memory, thu hồi mọi credential vừa logon trên host. "
                + "Reset mật khẩu đặc quyền + tài khoản vừa đăng nhập trong 24h trước đó.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
