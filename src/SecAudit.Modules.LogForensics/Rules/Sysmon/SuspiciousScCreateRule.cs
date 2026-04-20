using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1543.003 — Create or Modify System Process: Windows Service,
/// biến thể dùng <c>sc.exe create</c> trực tiếp thay vì service-install API.
///
/// Trùng mục đích với <see cref="BackdoorServiceRule"/> (đã có, bắt Event 4697/7045)
/// nhưng rule này nhắm vào CommandLine trong Sysmon Event 1 — bắt được ngay
/// KHOẢNH KHẮC gõ lệnh, kể cả khi Security log bị tắt ghi 4697. Cũng bắt
/// <c>New-Service</c> (PowerShell) và <c>net start</c> suspicious.
/// </summary>
public sealed class SuspiciousScCreateRule : IDetectionRule
{
    public string Id => "SYSMON-SC-CREATE";
    public string Name => "sc.exe tạo service tại thư mục đáng ngờ";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Tên binary các "service installer" tiện dụng cho attacker.
    /// </summary>
    private static readonly HashSet<string> ServiceInstallers = new(StringComparer.OrdinalIgnoreCase)
    {
        "sc.exe", "sc"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 1 — ProcessCreate (sc.exe create)",
        "MITRE ATT&CK T1543.003 — Windows Service",
        "Sigma: proc_creation_win_susp_sc_create.yml"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.process") { return; }

        var image = record.GetField("Image") ?? string.Empty;
        var imageName = SysmonHelpers.GetFileName(image);

        var commandLine = (record.GetField("CommandLine") ?? string.Empty);
        var cmdLower = commandLine.ToLowerInvariant();

        bool scCreate = ServiceInstallers.Contains(imageName)
            && (cmdLower.Contains(" create ", StringComparison.Ordinal)
                || cmdLower.Contains(" config ", StringComparison.Ordinal));

        bool newServicePs = (imageName == "powershell.exe" || imageName == "pwsh.exe")
            && cmdLower.Contains("new-service", StringComparison.Ordinal);

        if (!scCreate && !newServicePs) { return; }

        // Phân tích binPath= argument
        string? binPath = null;
        int idx = cmdLower.IndexOf("binpath=", StringComparison.Ordinal);
        if (idx > 0) { binPath = commandLine[(idx + 8)..].Trim('"', ' '); }
        else if (newServicePs)
        {
            idx = cmdLower.IndexOf("-binarypathname", StringComparison.Ordinal);
            if (idx > 0) { binPath = commandLine[(idx + 16)..].Trim('"', ' '); }
        }

        var reasons = new List<string>();
        if (binPath is not null && SysmonHelpers.IsInUserWritableLocation(binPath))
        {
            reasons.Add($"binPath trong thư mục user-writable ({binPath})");
        }
        if (cmdLower.Contains("powershell", StringComparison.Ordinal)
            && (cmdLower.Contains("-enc", StringComparison.Ordinal)
                || cmdLower.Contains("-encodedcommand", StringComparison.Ordinal)))
        {
            reasons.Add("binPath nhúng PowerShell encoded command");
        }
        if (cmdLower.Contains(" type= own", StringComparison.Ordinal)
            && cmdLower.Contains(" start= auto", StringComparison.Ordinal)
            && reasons.Count > 0)
        {
            reasons.Add("service cấu hình auto-start + type=own (persistence đầy đủ)");
        }

        if (reasons.Count == 0) { return; }

        var cmdPreview = commandLine.Length > 400 ? commandLine[..400] + "…" : commandLine;
        var key = imageName + "|" + (binPath ?? cmdPreview);
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"Service creation nghi vấn qua {imageName}",
            severity: Severity.Critical,
            category: "log-forensics.persistence",
            asset: $"host:{ctx.MachineName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"Image: {image}\nCommandLine: {cmdPreview}\n"
                + $"binPath: {binPath ?? "(không tách được)"}\n"
                + $"Lý do: {string.Join("; ", reasons)}",
            remediation:
                "Kiểm tra `sc.exe query` ngay trên host tìm service mới. Stop + delete service, "
                + "xoá binary, thu hash submit VT. Xác minh các service account có bị compromise không.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
