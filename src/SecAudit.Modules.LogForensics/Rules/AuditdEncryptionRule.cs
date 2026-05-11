using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects ransomware-style encryption activity from auditd records:
///
/// <list type="number">
///   <item><b>EXECVE with --encrypt flag</b> — process spawned with cipher-related
///         argv (<c>--encrypt</c>, <c>--cipher</c>, <c>--key</c>) emits a Critical
///         finding pointing at the executed binary path.</item>
///   <item><b>PATH burst of .locked / .encrypted files</b> — counts <c>type=PATH</c>
///         events touching files with ransomware-typical extensions; ≥3 such
///         CREATE events emits a Critical finding listing the affected paths.
///         This is the auditd-side smoking gun proving "files just got encrypted",
///         independent of any sudo log line.</item>
///   <item><b>EXECVE of hidden binary</b> in system path (<c>/usr/local/bin/.*</c>,
///         <c>/tmp/.*</c>, <c>/var/tmp/.*</c>) — High finding flagging implant
///         execution even if the operator never typed sudo (e.g. cron-spawned).</item>
/// </list>
/// </summary>
public sealed class AuditdEncryptionRule : IDetectionRule
{
    public string Id => "FOR-AUDITD";
    public string Name => "auditd: mã hoá / hidden-binary execution";

    private static readonly string[] EncryptedExts =
    {
        ".locked", ".encrypted", ".crypt", ".crypted", ".enc",
        ".wncry", ".ryk", ".lockbit", ".payment", ".pay2decrypt"
    };

    private static readonly string[] CryptoFlags =
    {
        "--encrypt", "--cipher", "--key=", " --key ", " -e ", " -c ",
        "--decrypt", "--passphrase"
    };

    private static readonly string[] HiddenBinaryHints =
    {
        "/usr/local/bin/.", "/usr/local/sbin/.", "/tmp/.", "/var/tmp/.",
        "/dev/shm/.", "/.crond", "/.beacon", "/.daemon"
    };

    private static readonly string[] EncryptRefs =
    {
        "MITRE ATT&CK T1486 — Data Encrypted for Impact",
        "MITRE ATT&CK T1059 — Command and Scripting Interpreter"
    };

    private static readonly string[] HiddenBinRefs =
    {
        "MITRE ATT&CK T1059 — Command and Scripting Interpreter",
        "MITRE ATT&CK T1564 — Hide Artifacts"
    };

    private readonly List<(string Ts, string Path, string SourceFile, long Offset)> _lockedPaths = new();
    private readonly HashSet<string> _emittedHidden = new(StringComparer.Ordinal);
    private readonly HashSet<string> _emittedCrypto = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(ctx);

        switch (record.EventKind)
        {
            case "audit.execve":
                CheckExecve(record, ctx);
                break;
            case "audit.path":
                CollectLockedPath(record);
                break;
            case "audit.syscall":
                CheckSyscallExe(record, ctx);
                break;
        }
    }

    private void CheckExecve(LogRecord r, ForensicsContext ctx)
    {
        var cmd = r.GetField("Command") ?? string.Empty;
        if (string.IsNullOrEmpty(cmd)) { return; }
        var lower = cmd.ToLowerInvariant();

        var matchedFlag = CryptoFlags.FirstOrDefault(f => lower.Contains(f, StringComparison.Ordinal));
        if (matchedFlag is null) { return; }

        var key = "CRYPTO:" + cmd;
        if (!_emittedCrypto.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-CRYPTO-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Quan sát execve gọi tham số mã hoá: {Truncate(cmd, 90)}",
            severity: Severity.Critical,
            category: "log-forensics.auditd-encrypt",
            asset: $"host:{ctx.MachineName}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] EXECVE: {cmd}\n"
                    + $"Cờ mã hoá khớp: \"{matchedFlag.Trim()}\"\n"
                    + $"Raw: {r.RawLine}",
            remediation: "Đây là bằng chứng từ auditd cho thấy tiến trình đã thực thi với "
                       + "đối số mã hoá. Xác định binary, người gọi (xem audit.syscall ngay trước "
                       + "EXECVE này), và phạm vi target. Cô lập máy nếu binary là hidden-name; "
                       + "thu thập memory dump trước reboot.",
            references: EncryptRefs));
    }

    private void CollectLockedPath(LogRecord r)
    {
        var path = r.GetField("Path") ?? string.Empty;
        if (string.IsNullOrEmpty(path)) { return; }

        var lower = path.ToLowerInvariant();
        var hit = false;
        foreach (var ext in EncryptedExts)
        {
            if (lower.EndsWith(ext, StringComparison.Ordinal)) { hit = true; break; }
        }
        if (!hit) { return; }

        var ts = r.Timestamp.ToString("o");
        _lockedPaths.Add((ts, path, r.SourceFile, r.SourceOffset));
    }

    private void CheckSyscallExe(LogRecord r, ForensicsContext ctx)
    {
        var exe = r.GetField("Exe") ?? string.Empty;
        if (string.IsNullOrEmpty(exe)) { return; }

        var matched = HiddenBinaryHints.FirstOrDefault(h => exe.Contains(h, StringComparison.Ordinal));
        if (matched is null) { return; }

        var key = "HIDDEN:" + exe;
        if (!_emittedHidden.Add(key)) { return; }

        var euid = r.GetField("EffectiveUser") ?? "(unknown)";
        ctx.Emit(Finding.Create(
            id: $"{Id}-HIDDEN-{Math.Abs(key.GetHashCode()):X8}",
            title: $"auditd: thực thi hidden-name binary {exe}",
            severity: Severity.High,
            category: "log-forensics.auditd-encrypt",
            asset: $"host:{ctx.MachineName}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] SYSCALL exe={exe}\n"
                    + $"Effective user: {euid}\n"
                    + $"Pattern khớp: \"{matched}\"\n"
                    + $"Raw: {r.RawLine}",
            remediation: "Binary có tên ẩn (bắt đầu bằng '.') trong system path là pattern "
                       + "kinh điển của implant Linux. Thu thập binary để phân tích, kiểm tra "
                       + "crontab + systemd để gỡ persistence, đối chiếu hash với threat intel.",
            references: HiddenBinRefs));
    }

    public void Flush(ForensicsContext ctx)
    {
        if (_lockedPaths.Count < 3) { return; }

        var sample = _lockedPaths.Take(8).ToList();
        var lines = string.Join("\n", sample.Select(p =>
            $"  [{p.SourceFile}:{p.Offset}] {p.Path}"));
        var more = _lockedPaths.Count - sample.Count;

        ctx.Emit(Finding.Create(
            id: $"{Id}-LOCKED-BURST",
            title: $"auditd ghi nhận {_lockedPaths.Count} file mã hoá (.locked/.encrypted/.crypt)",
            severity: Severity.Critical,
            category: "log-forensics.auditd-encrypt",
            asset: $"host:{ctx.MachineName}",
            evidence: $"Số file PATH event với đuôi đặc trưng ransomware: {_lockedPaths.Count}\n"
                    + $"Mẫu (top {sample.Count}):\n{lines}"
                    + (more > 0 ? $"\n... và {more} đường dẫn khác." : ""),
            remediation: "Kernel audit đã quan sát chuỗi tạo file mã hoá. Đây là bằng chứng "
                       + "không thể chối cãi rằng dữ liệu đã bị tác động. Cô lập host ngay; "
                       + "không trả tiền chuộc; sao lưu nguyên trạng đĩa làm bằng chứng pháp lý; "
                       + "khôi phục từ backup sạch.",
            references: EncryptRefs));
    }

    public void Reset()
    {
        _lockedPaths.Clear();
        _emittedHidden.Clear();
        _emittedCrypto.Clear();
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
