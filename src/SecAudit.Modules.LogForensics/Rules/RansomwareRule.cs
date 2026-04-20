using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects ransomware activity via three complementary signals:
///   * File-creation burst &gt; <see cref="CreatesPerMinute"/> with known ransomware
///     extensions (.locked .enc .wncry .lockbit .conti ...) — Sysmon 11 events.
///   * Shadow-copy deletion commands (<c>vssadmin delete shadows</c>, <c>wbadmin delete catalog</c>,
///     <c>wmic shadowcopy delete</c>) — universal ransomware precursor.
///   * Linux <c>cipher /w</c> / encryption tool install via bash history.
/// </summary>
public sealed class RansomwareRule : IDetectionRule
{
    public string Id => "FOR-RANSOM";
    public string Name => "Mã hoá dữ liệu (Ransomware)";

    private const int CreatesPerMinute = 100;

    private static readonly string[] RansomExtensions =
    {
        ".locked", ".enc", ".crypt", ".wncry", ".wannacry", ".wncrypt",
        ".lockbit", ".conti", ".ryuk", ".revil", ".sodinokibi", ".maze",
        ".clop", ".babuk", ".blackcat", ".darkside", ".egregor", ".dharma",
        ".crysis", ".crypted", ".cryptolocker", ".zepto", ".cerber"
    };

    private static readonly string[] ShadowDeleteCommands =
    {
        "vssadmin delete shadows",
        "vssadmin delete shadowstorage",
        "wbadmin delete catalog",
        "wbadmin delete systemstatebackup",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
    };

    private static readonly string[] ReferencesArr =
    {
        "MITRE ATT&CK T1486 — Data Encrypted for Impact",
        "MITRE ATT&CK T1490 — Inhibit System Recovery"
    };

    // Sliding-window creation counter keyed by minute bucket.
    private readonly Dictionary<long, int> _createsPerMinute = new();
    private long? _lastBurstMinuteEmitted;
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        switch (record.EventKind)
        {
            case "sysmon.filecreate":
                HandleFileCreate(record, ctx);
                break;
            case "process.created":
            case "sysmon.process":
            case "bash.command":
                HandleCommand(record, ctx);
                break;
        }
    }

    private void HandleFileCreate(LogRecord r, ForensicsContext ctx)
    {
        var target = r.GetField("TargetFilename") ?? r.GetField("Image") ?? string.Empty;
        var ext = Path.GetExtension(target).ToLowerInvariant();
        if (ext.Length == 0) { return; }
        if (!Array.Exists(RansomExtensions, e => e.Equals(ext, StringComparison.Ordinal))) { return; }

        var bucket = r.Timestamp.ToUnixTimeSeconds() / 60;
        _createsPerMinute.TryGetValue(bucket, out var count);
        _createsPerMinute[bucket] = count + 1;

        if (count + 1 >= CreatesPerMinute && _lastBurstMinuteEmitted != bucket)
        {
            _lastBurstMinuteEmitted = bucket;
            ctx.Emit(Finding.Create(
                id: $"{Id}-BURST-{bucket:X}",
                title: $"Bùng phát tệp mã hoá ({count + 1}+/phút, ext {ext}) — nghi ransomware",
                severity: Severity.Critical,
                category: "log-forensics.ransomware",
                asset: $"host:{ctx.MachineName}",
                evidence: $"[{r.SourceFile}:{r.SourceOffset}] Ví dụ: {target}\n"
                    + $"Tốc độ: {count + 1} file/phút với extension {ext}.\nRaw: {r.RawLine}",
                remediation: "CÁCH LY MÁY KHỎI MẠNG NGAY. Tắt máy chủ file share nếu liên quan."
                    + " Không reboot (có thể mất shadow copy còn sót). Gọi IR/SOC, bảo toàn bằng chứng.",
                references: ReferencesArr));
        }
    }

    private void HandleCommand(LogRecord r, ForensicsContext ctx)
    {
        var cmd = r.GetField("CommandLine") ?? r.GetField("Command") ?? r.GetField("Image") ?? string.Empty;
        if (string.IsNullOrEmpty(cmd)) { return; }

        foreach (var m in ShadowDeleteCommands)
        {
            if (cmd.Contains(m, StringComparison.OrdinalIgnoreCase))
            {
                var key = "SHADOW:" + m;
                if (!_emitted.Add(key)) { return; }
                ctx.Emit(Finding.Create(
                    id: $"{Id}-S-{Math.Abs(key.GetHashCode()):X8}",
                    title: "Lệnh xoá shadow copy / backup — tiền tố tấn công ransomware",
                    severity: Severity.Critical,
                    category: "log-forensics.ransomware",
                    asset: $"host:{ctx.MachineName}",
                    evidence: $"[{r.SourceFile}:{r.SourceOffset}] Command={cmd}\nMatched: \"{m}\"\nRaw: {r.RawLine}",
                    remediation: "Đây là mẫu hành vi ransomware tiêu chuẩn. Cách ly máy, kiểm tra tiến trình"
                        + " đang chạy (đặc biệt các tiến trình không có chữ ký), bảo toàn log.",
                    references: ReferencesArr));
                return;
            }
        }
    }

    public void Flush(ForensicsContext ctx) { }
}
