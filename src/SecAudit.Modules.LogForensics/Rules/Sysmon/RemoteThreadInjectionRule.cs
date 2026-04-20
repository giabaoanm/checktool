using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1055 — Process Injection (Create Remote Thread variant).
///
/// Sysmon Event 8 ghi khi một process gọi <c>CreateRemoteThread</c> vào process
/// khác. Đây là API classic cho DLL injection, shellcode injection, và reflective
/// loading. Trong môi trường sạch số lượng event 8 CỰC thấp — chủ yếu là debugger,
/// AV scan, và một số monitoring agent.
///
/// <para>
/// Heuristic: nếu SourceImage nằm trong <see cref="SysmonHelpers.UserWritableMarkers"/>
/// hoặc TargetImage là một trong các process nhạy cảm (lsass/winlogon/explorer/
/// services), emit Critical. Cross-user-session injection cũng được coi là High.
/// </para>
/// </summary>
public sealed class RemoteThreadInjectionRule : IDetectionRule
{
    public string Id => "SYSMON-INJECT";
    public string Name => "Tiêm thread từ xa (CreateRemoteThread injection)";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Target hay bị nhắm để persistence/credential theft/stealth. Bất kỳ inject
    /// nào vào các process này đều là Critical kể cả khi source trông bình thường.
    /// </summary>
    private static readonly HashSet<string> SensitiveTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass.exe", "winlogon.exe", "explorer.exe", "services.exe",
        "svchost.exe", "csrss.exe", "wininit.exe", "spoolsv.exe",
        "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe"
    };

    /// <summary>
    /// Các monitoring agent hợp lệ hay dùng CreateRemoteThread — whitelist để giảm FP.
    /// </summary>
    private static readonly HashSet<string> BenignSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "msmpeng.exe", "mssense.exe", "sentinelagent.exe",
        "cylancesvc.exe", "crowdstrike.exe", "csfalconservice.exe"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 8 — CreateRemoteThread",
        "MITRE ATT&CK T1055 — Process Injection",
        "Sigma: sysmon_createremotethread_loaddll.yml"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.createremotethread") { return; }

        var sourceImage = record.GetField("SourceImage") ?? string.Empty;
        var sourceName = SysmonHelpers.GetFileName(sourceImage);
        if (BenignSources.Contains(sourceName)) { return; }

        var targetImage = record.GetField("TargetImage") ?? string.Empty;
        var targetName = SysmonHelpers.GetFileName(targetImage);

        bool sensitiveTarget = SensitiveTargets.Contains(targetName);
        bool sourceFromUserSpace = SysmonHelpers.IsInUserWritableLocation(sourceImage);

        // Nếu cả source & target đều "bình thường" thì bỏ qua (giảm noise từ tool hợp lệ).
        if (!sensitiveTarget && !sourceFromUserSpace) { return; }

        var key = sourceName + "→" + targetName;
        if (!_emitted.Add(key)) { return; }

        var severity = sensitiveTarget ? Severity.Critical : Severity.High;
        var reason = sensitiveTarget
            ? $"tiêm vào process nhạy cảm {targetName}"
            : $"source {sourceName} chạy từ thư mục user-writable ({sourceImage})";

        var startAddr = record.GetField("StartAddress") ?? "(unknown)";
        var startModule = record.GetField("StartModule") ?? "(not mapped — có thể là shellcode thuần)";

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"CreateRemoteThread: {sourceName} → {targetName}",
            severity: severity,
            category: "log-forensics.process-injection",
            asset: $"process:{targetName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"Source: {sourceImage}\n"
                + $"Target: {targetImage}\n"
                + $"StartAddress: {startAddr}\nStartModule: {startModule}\n"
                + $"Lý do: {reason}",
            remediation:
                "Dump memory của cả source và target process để xác minh shellcode/reflective DLL. "
                + "Nếu target là lsass/winlogon: reset credential, cô lập host ngay. "
                + "Báo cáo với đội IR (Incident Response).",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
