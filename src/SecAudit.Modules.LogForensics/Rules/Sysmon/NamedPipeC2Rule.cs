using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1021.002 — Remote Services: SMB/Windows Admin Shares,
/// sub-technique named-pipe lateral movement / C2.
///
/// Sysmon Event 17 (PipeCreated) + Event 18 (PipeConnected). Cobalt Strike
/// BEACON, Meterpreter và nhiều RAT hay dùng named pipe để:
/// <list type="bullet">
/// <item>Inter-process communication giữa payload và injected DLL.</item>
/// <item>SMB pivoting lateral movement (beacon SMB).</item>
/// <item>Privilege escalation qua impersonate pipe client.</item>
/// </list>
///
/// <para>
/// Rule dựa trên hai lớp detect:
/// 1. Pattern name mặc định / biết trước của CS/Metasploit (xem
///    <see cref="SysmonHelpers.CobaltStrikePipePatterns"/>).
/// 2. Pipe được tạo bởi process ở vị trí user-writable — DLL hợp lệ không thường
///    làm điều này.
/// </para>
/// </summary>
public sealed class NamedPipeC2Rule : IDetectionRule
{
    public string Id => "SYSMON-PIPE";
    public string Name => "Named pipe đáng ngờ (Cobalt Strike / Meterpreter C2)";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// Pipe name hệ thống phổ biến — bỏ qua nếu không kết hợp với dấu hiệu khác.
    /// `\lsass` / `\ntsvcs` / `\wkssvc` là pipe RPC hợp lệ.
    /// </summary>
    private static readonly HashSet<string> BenignPipeSubstrings = new(StringComparer.OrdinalIgnoreCase)
    {
        @"\lsass", @"\ntsvcs", @"\winreg", @"\samr",
        @"\PIPE\terminal server", @"\PIPE\atsvc", @"\PIPE\eventlog",
        @"\PIPE\ROUTER", @"\PIPE\InitShutdown", @"\PIPE\lsm_api_service"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 17/18 — PipeCreate/PipeConnect",
        "MITRE ATT&CK T1021.002 — Remote Services (SMB/Admin Shares)",
        "MITRE ATT&CK T1055 — Process Injection (pipe IPC)",
        "Cobalt Strike Named Pipe IOCs (CISA AA22-152A)"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.pipecreate" && record.EventKind != "sysmon.pipeconnect") { return; }

        var pipeName = record.GetField("PipeName") ?? string.Empty;
        if (string.IsNullOrEmpty(pipeName)) { return; }

        var image = record.GetField("Image") ?? string.Empty;
        var imageName = SysmonHelpers.GetFileName(image);

        // Match Cobalt Strike / Metasploit default patterns.
        string? csMatch = null;
        foreach (var p in SysmonHelpers.CobaltStrikePipePatterns)
        {
            if (pipeName.Contains(p, StringComparison.OrdinalIgnoreCase)) { csMatch = p; break; }
        }

        bool fromUserSpace = SysmonHelpers.IsInUserWritableLocation(image);
        bool isBenign = false;
        foreach (var b in BenignPipeSubstrings)
        {
            if (pipeName.Contains(b, StringComparison.OrdinalIgnoreCase)) { isBenign = true; break; }
        }

        Severity? severity = null;
        string? reason = null;

        if (csMatch is not null)
        {
            severity = Severity.Critical;
            reason = $"pipe name khớp pattern Cobalt Strike / Meterpreter: \"{csMatch}\"";
        }
        else if (fromUserSpace && !isBenign)
        {
            severity = Severity.High;
            reason = $"pipe được tạo bởi binary ở thư mục user-writable ({image})";
        }
        else if (!isBenign && LooksLikeRandomPipeName(pipeName))
        {
            severity = Severity.Medium;
            reason = $"tên pipe có đặc điểm random/giả danh ({pipeName})";
        }

        if (severity is null) { return; }

        var key = imageName + "|" + pipeName.ToLowerInvariant();
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"Named pipe đáng ngờ: {pipeName} ({imageName})",
            severity: severity.Value,
            category: "log-forensics.c2-lateral-movement",
            asset: $"process:{imageName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"EventKind: {record.EventKind}\n"
                + $"PipeName: {pipeName}\n"
                + $"Image: {image}\n"
                + $"Lý do: {reason}",
            remediation:
                "Dump memory process sở hữu pipe, tìm BEACON signature. "
                + "Block SMB outbound trên firewall nếu chưa. Kiểm tra các host khác trong "
                + "subnet xem có connect vào pipe này không (= dấu hiệu lateral movement).",
            references: ReferencesArr));
    }

    /// <summary>
    /// Pipe name legitimate thường ngắn, có ý nghĩa. Pipe random 8+ ký tự hex là dấu
    /// hiệu. Heuristic đơn giản: >70% ký tự là hex digit VÀ length >= 8.
    /// </summary>
    private static bool LooksLikeRandomPipeName(string pipe)
    {
        var idx = pipe.LastIndexOf('\\');
        var tail = idx < 0 ? pipe : pipe[(idx + 1)..];
        if (tail.Length < 8) { return false; }
        int hex = 0;
        foreach (var c in tail)
        {
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) { hex++; }
        }
        return hex * 100 / tail.Length >= 70;
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
