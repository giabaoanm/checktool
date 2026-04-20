using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1546.003 — Event Triggered Execution: WMI Event Subscription.
/// (Cũng dính T1047 — Windows Management Instrumentation.)
///
/// Sysmon Event 19/20/21 log các thao tác trên <c>root\subscription</c> namespace:
/// <list type="bullet">
/// <item>Event 19 — WmiEventFilter tạo mới</item>
/// <item>Event 20 — WmiEventConsumer tạo mới (ActiveScriptEventConsumer, CommandLineEventConsumer)</item>
/// <item>Event 21 — WmiEventConsumerToFilter (binding)</item>
/// </list>
///
/// <para>
/// APT29, Turla, Leviathan là vài nhóm nổi tiếng dùng WMI subscription cho
/// persistence vô hình (không có Run key, không có Task Scheduler, không có Service).
/// Chỉ cần 1 trong 3 event này trong log đã đáng để điều tra — admin hợp lệ
/// RẤT hiếm khi tạo WMI consumer tự build.
/// </para>
/// </summary>
public sealed class WmiPersistenceRule : IDetectionRule
{
    public string Id => "SYSMON-WMI";
    public string Name => "WMI Event Subscription persistence";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Các Consumer/Filter do Microsoft/Defender tạo mặc định — whitelist để tránh FP.
    /// Danh sách đã deliberately ngắn; mọi thứ khác đều cần xem xét.
    /// </summary>
    private static readonly HashSet<string> BenignNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SCM Event Log Filter", "SCM Event Log Consumer",
        "BVTFilter", "BVTConsumer",
        "NTEventLogEventConsumer"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 19/20/21 — WMI Event Subscription",
        "MITRE ATT&CK T1546.003 — Event Triggered Execution: WMI Subscription",
        "CISA Alert AA21-148A — APT29 tradecraft"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        bool isWmi = record.EventKind is "sysmon.wmifilter"
            or "sysmon.wmiconsumer"
            or "sysmon.wmibinding";
        if (!isWmi) { return; }

        var name = record.GetField("Name") ?? record.GetField("Operation") ?? "(unknown)";
        if (BenignNames.Contains(name)) { return; }

        // Dedup theo (kind, name) — một chiến dịch thường tạo 1 filter + 1 consumer + 1 binding.
        var key = record.EventKind + "|" + name;
        if (!_emitted.Add(key)) { return; }

        // Consumer chứa script trực tiếp (ActiveScript / CommandLineEventConsumer) là cờ đỏ nặng.
        var consumerType = record.GetField("Type") ?? string.Empty;
        var destination = record.GetField("Destination")
            ?? record.GetField("DestinationExecutable")
            ?? record.GetField("ScriptFileName")
            ?? record.GetField("CommandLineTemplate")
            ?? "(not captured)";
        var query = record.GetField("Query") ?? "(not captured)";
        var user = record.GetField("User") ?? "(unknown)";

        Severity severity = record.EventKind == "sysmon.wmibinding"
            ? Severity.Critical   // binding = consumer + filter đã wire — persistence đã active
            : Severity.High;

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"WMI Event Subscription đáng ngờ: {name} ({record.EventKind.Replace("sysmon.", "")})",
            severity: severity,
            category: "log-forensics.persistence",
            asset: $"host:{ctx.MachineName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"Kind: {record.EventKind}\nUser: {user}\nName: {name}\n"
                + $"Type: {consumerType}\nDestination/Template: {destination}\n"
                + $"Query: {query}",
            remediation:
                "Liệt kê toàn bộ subscription: `Get-WMIObject -Namespace root\\subscription -Class __EventFilter`, "
                + "`__EventConsumer`, `__FilterToConsumerBinding`. Xoá các entry không whitelist. "
                + "Đây là persistence cấp APT — cần dump volume, điều tra các host khác trong AD cùng OU.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
