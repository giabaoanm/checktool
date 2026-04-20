using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects destructive commands intended to wipe data or tamper evidence:
///   * Windows: <c>wevtutil cl</c>, <c>fsutil file setZeroData</c>, <c>cipher /w</c>,
///     <c>format</c>, <c>diskpart clean</c>, <c>del /f /s /q</c> against system paths.
///   * Linux (bash.command / sudo.command): <c>rm -rf /</c>, <c>shred</c>,
///     <c>dd if=/dev/zero of=/dev/sda</c>, <c>mkfs</c>, <c>wipefs</c>.
/// All hits are Critical — these commands have no legitimate day-to-day use.
/// </summary>
public sealed class DataDestructionRule : IDetectionRule
{
    public string Id => "FOR-WIPE";
    public string Name => "Phá huỷ dữ liệu (Data destruction / wiping)";

    private static readonly string[] WindowsMarkers =
    {
        "wevtutil cl ",
        "wevtutil /cl ",
        "fsutil file setZeroData",
        "cipher /w:",
        "format c:",
        "format /q",
        "diskpart",            // combined with "clean" via heuristic below
        "del /f /s /q c:\\",
        "del /f /s /q %systemroot%",
        "rmdir /s /q c:\\"
    };

    private static readonly string[] LinuxMarkers =
    {
        "rm -rf /",
        "rm -rf /*",
        "rm -rf --no-preserve-root",
        "shred -u ",
        "shred -vfz",
        "dd if=/dev/zero of=/dev/",
        "dd if=/dev/urandom of=/dev/",
        "mkfs.",
        "wipefs -a /dev/"
    };

    private static readonly string[] ReferencesArr =
    {
        "MITRE ATT&CK T1485 — Data Destruction",
        "MITRE ATT&CK T1070 — Indicator Removal"
    };

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        var cmd = record.GetField("CommandLine") ?? record.GetField("Command") ?? string.Empty;
        if (string.IsNullOrEmpty(cmd)) { return; }

        var lower = cmd.ToLowerInvariant();
        bool isLinuxCtx = record.Os.Equals("linux", StringComparison.OrdinalIgnoreCase)
            || record.EventKind is "bash.command" or "sudo.command";

        string? matched = null;

        if (isLinuxCtx)
        {
            foreach (var m in LinuxMarkers)
            {
                if (lower.Contains(m, StringComparison.Ordinal)) { matched = m; break; }
            }
        }
        else
        {
            foreach (var m in WindowsMarkers)
            {
                if (lower.Contains(m.ToLowerInvariant(), StringComparison.Ordinal)) { matched = m; break; }
            }
            // diskpart + clean heuristic: catch multi-line scripts
            if (matched is null && lower.Contains("diskpart", StringComparison.Ordinal)
                && lower.Contains("clean", StringComparison.Ordinal))
            {
                matched = "diskpart ... clean";
            }
        }
        if (matched is null) { return; }

        var key = "WIPE:" + matched + ":" + record.SourceFile + ":" + record.SourceOffset;
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Lệnh phá huỷ dữ liệu: \"{matched.Trim()}\"",
            severity: Severity.Critical,
            category: "log-forensics.data-destruction",
            asset: $"host:{ctx.MachineName}",
            evidence: $"[{record.SourceFile}:{record.SourceOffset}] Command={cmd}\nMatched: \"{matched}\"\nRaw: {record.RawLine}",
            remediation: "Cách ly máy ngay. Kiểm tra tài khoản đã chạy lệnh này và xem xét nguồn xâm nhập."
                + " Phục hồi dữ liệu từ backup sạch; thu thập image ổ đĩa trước khi reboot.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
}
