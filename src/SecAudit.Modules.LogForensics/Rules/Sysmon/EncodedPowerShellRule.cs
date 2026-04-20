using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1059.001 — Command and Scripting Interpreter: PowerShell,
/// đặc biệt là biến thể encoded / obfuscated.
///
/// Sysmon Event 1 (ProcessCreate) ghi CommandLine đầy đủ. Các flag
/// <c>-EncodedCommand</c> / <c>-enc</c> / <c>-ec</c> / <c>FromBase64String</c> /
/// <c>IEX (New-Object Net.WebClient).DownloadString</c> là cờ đỏ gần như tuyệt đối
/// — admin hợp lệ gần như không bao giờ dùng encoded command (khó maintain).
///
/// <para>
/// Cũng bắt cả pwsh.exe (PowerShell 7) và các alias (powershell_ise, powershell*.exe).
/// Trường hợp ngắn + không có pattern nghi vấn thì skip — tránh FP từ script admin.
/// </para>
/// </summary>
public sealed class EncodedPowerShellRule : IDetectionRule
{
    public string Id => "SYSMON-PSENC";
    public string Name => "PowerShell encoded / obfuscated execution";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Substring trong command line là signature mạnh. Khớp 1 trong danh sách → flag.
    /// Dành cho <c>powershell.exe</c>/<c>pwsh.exe</c> — các process khác dùng các
    /// pattern này trong path/argument có thể là bình thường.
    /// </summary>
    private static readonly string[] EncodedMarkers =
    {
        " -enc ", " -ec ", " -encodedcommand", "-e jab", "-e iex",
        "frombase64string", "[system.convert]::frombase64",
        "iex (new-object", "invoke-expression", "downloadstring(",
        "downloadfile(", "net.webclient", "hidden -nop -w",
        "-noprofile -windowstyle hidden",
        "[scriptblock]::create", "[char[]](", "-bxor ",
        "$ExecutionContext.InvokeCommand".ToLowerInvariant()
    };

    private static readonly string[] PowerShellExes =
    {
        "powershell.exe", "pwsh.exe", "powershell_ise.exe"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 1 — ProcessCreate",
        "MITRE ATT&CK T1059.001 — PowerShell",
        "Sigma: proc_creation_win_powershell_encoded.yml"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.process") { return; }

        var image = record.GetField("Image") ?? string.Empty;
        var imageName = SysmonHelpers.GetFileName(image);
        if (Array.IndexOf(PowerShellExes, imageName) < 0) { return; }

        var commandLine = (record.GetField("CommandLine") ?? string.Empty).ToLowerInvariant();
        if (commandLine.Length == 0) { return; }

        // Ngắn + không có marker → admin interactive → bỏ qua
        string? matched = null;
        foreach (var m in EncodedMarkers)
        {
            if (commandLine.Contains(m, StringComparison.Ordinal)) { matched = m; break; }
        }
        if (matched is null) { return; }

        // Dedup theo prefix 40 ký tự của commandline (nhiều lần chạy cùng encoded
        // command = cùng prefix). Đủ stable, tránh spam.
        var fingerprint = commandLine.Length > 40 ? commandLine[..40] : commandLine;
        var key = imageName + "|" + fingerprint;
        if (!_emitted.Add(key)) { return; }

        var parent = record.GetField("ParentImage") ?? "(unknown)";
        var user = record.GetField("User") ?? "(unknown)";

        // Severity: nếu parent là suspicious (Office / browser) → Critical; còn lại High.
        var parentName = SysmonHelpers.GetFileName(parent);
        var severity = Array.IndexOf(SysmonHelpers.SuspiciousParents, parentName) >= 0
            ? Severity.Critical
            : Severity.High;

        // Cắt command line dài để không phá grid. Người dùng có thể xem raw trong evidence bundle.
        var clPreview = commandLine.Length > 500 ? commandLine[..500] + "…[truncated]" : commandLine;

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"PowerShell thực thi lệnh mã hoá/obfuscated (marker: {matched.Trim()})",
            severity: severity,
            category: "log-forensics.suspicious-execution",
            asset: $"process:{imageName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"User: {user}\nParent: {parent}\n"
                + $"Image: {image}\nCommandLine: {clPreview}\n"
                + $"Marker trúng: \"{matched.Trim()}\"",
            remediation:
                "Decode chuỗi base64 (nếu có) bằng sandbox cô lập. Kiểm tra URL download, "
                + "hash payload. Bật thêm Script Block Logging (Event 4104) để thu raw script. "
                + "Nếu parent là Office: điều tra email phishing, quarantine mail gốc.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
