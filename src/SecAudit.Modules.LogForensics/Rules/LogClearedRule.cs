using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Windows Event 1102 (Security log cleared) and 104 (System log cleared) are the
/// canonical "covering tracks" indicator. Always emits a Critical because legitimate
/// admins almost never clear logs — and if they did, SIEM should know.
/// </summary>
public sealed class LogClearedRule : IDetectionRule
{
    public string Id => "FOR-CLEAR";
    public string Name => "Nhật ký bị xoá (Covering tracks)";

    private static readonly string[] ReferencesArr =
    {
        "Windows Event ID 1102 / 104",
        "MITRE ATT&CK T1070.001 — Indicator Removal: Clear Windows Event Logs"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        var r = record;
        if (r.EventKind != "log.cleared") { return; }
        var user = r.GetField("SubjectUserName") ?? r.GetField("UserName") ?? "(unknown)";
        var domain = r.GetField("SubjectDomainName") ?? string.Empty;

        ctx.Emit(Finding.Create(
            id: $"{Id}-{r.SourceOffset:X}",
            title: "Nhật ký Windows đã bị xoá — dấu hiệu che dấu hành vi",
            severity: Severity.Critical,
            category: "log-forensics.evidence-tampering",
            asset: $"host:{ctx.MachineName}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] Tài khoản {domain}\\{user}"
                + $" đã xoá log lúc {r.Timestamp:u}\nRaw: {r.RawLine}",
            remediation: "Xác minh với người quản trị xem có kế hoạch maintenance không."
                + " Nếu không: cách ly máy ngay, thu thập ổ đĩa forensics, gửi lên SIEM/SOC.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
}
