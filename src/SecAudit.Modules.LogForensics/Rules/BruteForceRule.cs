using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Raises Critical when ≥<see cref="FailThreshold"/> failed logons share the same
/// target user OR source IP inside <see cref="WindowSeconds"/>. Covers Windows 4625
/// and Linux sshd "Failed password" / "Invalid user" uniformly because both emit
/// <c>logon.failed</c> with fields TargetUserName and IpAddress normalized.
/// </summary>
public sealed class BruteForceRule : IDetectionRule
{
    public string Id => "FOR-BRUTE";
    public string Name => "Dò mật khẩu (Password brute-force)";

    private const int FailThreshold = 10;
    private const int WindowSeconds = 600;

    // key -> (list of record refs up to threshold, first_ts)
    private readonly Dictionary<string, List<(DateTimeOffset ts, string raw, string source, long line)>> _byUser = new();
    private readonly Dictionary<string, List<(DateTimeOffset ts, string raw, string source, long line)>> _byIp = new();
    private readonly HashSet<string> _alreadyEmittedUser = new();
    private readonly HashSet<string> _alreadyEmittedIp = new();

    private static readonly string[] ReferencesArr =
    {
        "MITRE ATT&CK T1110 — Brute Force",
        "Windows Event ID 4625",
        "Linux sshd Failed password"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        var r = record;
        if (r.EventKind != "logon.failed") { return; }
        var user = r.GetField("TargetUserName");
        var ip = r.GetField("IpAddress");

        if (!string.IsNullOrWhiteSpace(user))
        {
            Accumulate(_byUser, user!.ToLowerInvariant(), r, ctx, isUser: true);
        }
        if (!string.IsNullOrWhiteSpace(ip))
        {
            Accumulate(_byIp, ip!, r, ctx, isUser: false);
        }
    }

    private void Accumulate(
        Dictionary<string, List<(DateTimeOffset, string, string, long)>> map,
        string key, LogRecord r, ForensicsContext ctx, bool isUser)
    {
        if (!map.TryGetValue(key, out var list))
        {
            list = new List<(DateTimeOffset, string, string, long)>();
            map[key] = list;
        }
        list.Add((r.Timestamp, r.RawLine, r.SourceFile, r.SourceOffset));

        // drop entries older than window
        var cutoff = r.Timestamp.AddSeconds(-WindowSeconds);
        list.RemoveAll(x => x.Item1 < cutoff);

        if (list.Count < FailThreshold) { return; }

        var emittedSet = isUser ? _alreadyEmittedUser : _alreadyEmittedIp;
        if (!emittedSet.Add(key)) { return; }

        var evidence = string.Join("\n", list.TakeLast(5).Select(x =>
            $"  [{x.Item3}:{x.Item4}] {x.Item2}"));
        var title = isUser
            ? $"Dò mật khẩu — tài khoản \"{key}\" bị thử sai {list.Count}+ lần"
            : $"Dò mật khẩu — từ địa chỉ {key} thử sai {list.Count}+ lần";
        var sev = list.Count >= FailThreshold * 3 ? Severity.Critical : Severity.High;

        ctx.Emit(Finding.Create(
            id: $"{Id}-{(isUser ? "U" : "I")}-{Math.Abs(key.GetHashCode()):X8}",
            title: title,
            severity: sev,
            category: "log-forensics.brute-force",
            asset: isUser ? $"user:{key}" : $"ip:{key}",
            evidence: $"Phát hiện {list.Count} lần đăng nhập thất bại trong {WindowSeconds}s:\n{evidence}",
            remediation: isUser
                ? $"Khoá hoặc buộc đổi mật khẩu tài khoản {key}; kiểm tra đăng nhập thành công sau đó."
                : $"Chặn IP {key} tại firewall/fail2ban; kiểm tra có ESTABLISHED session từ IP này không.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { /* no-op, events emit in Observe */ }

    public void Reset()
    {
        _byUser.Clear();
        _byIp.Clear();
        _alreadyEmittedUser.Clear();
        _alreadyEmittedIp.Clear();
    }
}
