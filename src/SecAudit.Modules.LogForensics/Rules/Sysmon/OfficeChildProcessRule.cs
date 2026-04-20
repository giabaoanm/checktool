using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1566 (Phishing) / T1204 (User Execution) / T1059 (Interpreter).
///
/// Microsoft Office, Adobe Reader, WordPad spawn ra shell/script là signature
/// kinh điển cho macro-based phishing. Winword.exe → powershell.exe trong
/// môi trường doanh nghiệp bình thường KHÔNG BAO GIỜ xảy ra.
///
/// <para>
/// Rule này cũng phát hiện các chain đáng ngờ khác:
/// <list type="bullet">
/// <item>services.exe → powershell.exe → (persistence via service)</item>
/// <item>explorer.exe → cmd.exe /c (auto-run từ startup folder)</item>
/// <item>rundll32.exe từ thư mục user-writable</item>
/// </list>
/// </para>
/// </summary>
public sealed class OfficeChildProcessRule : IDetectionRule
{
    public string Id => "SYSMON-OFFICE-CHAIN";
    public string Name => "Office/Reader spawn shell-script (macro phishing chain)";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 1 — ProcessCreate (parent→child chain)",
        "MITRE ATT&CK T1566.001 — Spearphishing Attachment",
        "MITRE ATT&CK T1204.002 — User Execution: Malicious File",
        "MITRE ATT&CK T1059 — Command and Scripting Interpreter"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.process") { return; }

        var parent = record.GetField("ParentImage") ?? string.Empty;
        var child = record.GetField("Image") ?? string.Empty;
        if (string.IsNullOrEmpty(parent) || string.IsNullOrEmpty(child)) { return; }

        var parentName = SysmonHelpers.GetFileName(parent);
        var childName = SysmonHelpers.GetFileName(child);

        bool parentIsSuspicious = Array.IndexOf(SysmonHelpers.SuspiciousParents, parentName) >= 0;
        bool childIsShell = Array.IndexOf(SysmonHelpers.ShellChildren, childName) >= 0;
        if (!parentIsSuspicious || !childIsShell) { return; }

        var key = parentName + "→" + childName;
        if (!_emitted.Add(key)) { return; }

        var commandLine = record.GetField("CommandLine") ?? string.Empty;
        var user = record.GetField("User") ?? "(unknown)";
        var parentCmd = record.GetField("ParentCommandLine") ?? string.Empty;

        // Cắt command line cho evidence readable.
        var clPreview = commandLine.Length > 400 ? commandLine[..400] + "…[truncated]" : commandLine;
        var parentCmdPreview = parentCmd.Length > 200 ? parentCmd[..200] + "…" : parentCmd;

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key + "|" + commandLine)}",
            title: $"Chuỗi nghi vấn phishing: {parentName} spawn {childName}",
            severity: Severity.Critical,
            category: "log-forensics.phishing-chain",
            asset: $"process:{parentName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"User: {user}\n"
                + $"Parent: {parent}\n  ParentCmd: {parentCmdPreview}\n"
                + $"Child : {child}\n  ChildCmd : {clPreview}",
            remediation:
                "Cách ly máy khỏi mạng. Truy quét email inbox của user tìm attachment đính kèm trong "
                + "24h trước đó (DOC/DOCM/XLSM/PDF). Báo IT quarantine mail gốc trên Exchange. "
                + "Reset mật khẩu user. Dump memory winword/excel process nếu còn chạy.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
