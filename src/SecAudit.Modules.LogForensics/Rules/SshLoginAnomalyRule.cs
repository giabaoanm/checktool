using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects two high-signal SSH patterns that the previous rule set missed:
///
/// <list type="number">
///   <item><b>SSH brute-force</b> — counts <c>logon.failed</c> per IP across all
///         observed auth.log lines (incl. rotated <c>auth.log.*.gz</c>) and emits
///         a single High finding listing the worst sources.</item>
///   <item><b>Suspicious accepted password login</b> — emits Critical when a
///         <c>logon.success</c> with <c>Method=password</c> arrives from a public
///         IP that EITHER (a) had ≥5 prior failed attempts (brute-force succeeded),
///         OR (b) the user normally only logs in via <c>publickey</c> from a
///         different IP (anomalous credential use). This is the classic
///         "they finally guessed it" / "stolen-password" smoking-gun pattern.</item>
/// </list>
///
/// <para>RFC1918 / loopback / link-local IPs are skipped — only public-routable
/// sources count toward both detections.</para>
/// </summary>
public sealed class SshLoginAnomalyRule : IDetectionRule
{
    public string Id => "FOR-SSH-ANOMALY";
    public string Name => "Bất thường đăng nhập SSH";

    private const int FailureThresholdForFinding = 100;
    private const int FailureCountForBruteSuccess = 5;

    private readonly Dictionary<string, int> _failedByIp = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> _publickeyIpsPerUser =
        new(StringComparer.Ordinal);
    private readonly List<(string Ts, string User, string Ip)> _suspiciousPasswordLogins = new();
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    private static readonly string[] BruteForceRefs =
    {
        "MITRE ATT&CK T1110 — Brute Force",
        "MITRE ATT&CK T1110.001 — Password Guessing"
    };

    private static readonly string[] StolenAuthRefs =
    {
        "MITRE ATT&CK T1078 — Valid Accounts",
        "MITRE ATT&CK T1110 — Brute Force"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(ctx);
        if (record.EventKind is not ("logon.failed" or "logon.success"))
        {
            return;
        }

        var ip = record.GetField("IpAddress") ?? record.GetField("Ip") ?? string.Empty;
        var user = record.GetField("TargetUserName") ?? record.GetField("UserName") ?? string.Empty;
        if (string.IsNullOrEmpty(ip) || !IsPublicRoutable(ip))
        {
            // Could still be relevant for internal lateral movement, but for v1 we
            // only care about Internet-sourced SSH events to keep noise down.
            if (record.EventKind == "logon.success"
                && (record.GetField("Method") ?? "").Equals("publickey", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(ip))
            {
                AddPublickeyIp(user, ip);
            }
            return;
        }

        if (record.EventKind == "logon.failed")
        {
            _failedByIp[ip] = _failedByIp.TryGetValue(ip, out var c) ? c + 1 : 1;
            return;
        }

        // logon.success
        var method = record.GetField("Method") ?? "other";
        if (method.Equals("publickey", StringComparison.OrdinalIgnoreCase))
        {
            AddPublickeyIp(user, ip);
            return;
        }
        if (!method.Equals("password", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var failedCount = _failedByIp.TryGetValue(ip, out var f) ? f : 0;
        var userUsesKey = _publickeyIpsPerUser.TryGetValue(user, out var keyIps)
            && keyIps.Count > 0 && !keyIps.Contains(ip);

        if (failedCount < FailureCountForBruteSuccess && !userUsesKey)
        {
            return;
        }

        var key = $"ACCEPT:{user}@{ip}";
        if (!_emitted.Add(key))
        {
            return;
        }

        var ts = record.Timestamp.ToString("o");
        _suspiciousPasswordLogins.Add((ts, user, ip));

        var reasons = new List<string>();
        if (failedCount >= FailureCountForBruteSuccess)
        {
            reasons.Add($"IP đã có {failedCount} lần thất bại trước đó (brute-force pattern)");
        }
        if (userUsesKey)
        {
            reasons.Add("user này thường đăng nhập publickey từ IP khác — đăng nhập password lần này là bất thường");
        }

        ctx.Emit(Finding.Create(
            id: $"{Id}-ACCEPT-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Đăng nhập SSH password đáng ngờ: {user}@{ip}",
            severity: Severity.Critical,
            category: "log-forensics.ssh-anomaly",
            asset: $"user:{user}@{ip}",
            evidence: $"[{record.SourceFile}:{record.SourceOffset}]\n"
                    + $"User: {user}\nIP nguồn: {ip}\nThời gian: {ts}\n"
                    + $"Lý do: {string.Join("; ", reasons)}\n"
                    + $"Raw: {record.RawLine}",
            remediation: "Coi đây là phiên xâm nhập đến khi chứng minh ngược lại. "
                       + "1) Cô lập host khỏi mạng. "
                       + "2) Đổi toàn bộ chứng danh user, vô hiệu hoá đăng nhập password (chỉ giữ public-key). "
                       + "3) Soát mọi lệnh đã chạy sau timestamp này (sudo.log, .bash_history, audit.log). "
                       + "4) Block IP nguồn ở firewall + thêm vào blocklist nội bộ.",
            references: StolenAuthRefs));
    }

    private void AddPublickeyIp(string user, string ip)
    {
        if (!_publickeyIpsPerUser.TryGetValue(user, out var set))
        {
            set = new HashSet<string>(StringComparer.Ordinal);
            _publickeyIpsPerUser[user] = set;
        }
        set.Add(ip);
    }

    public void Flush(ForensicsContext ctx)
    {
        if (_failedByIp.Count == 0)
        {
            return;
        }

        var topAttackers = _failedByIp
            .Where(kv => kv.Value >= FailureThresholdForFinding)
            .OrderByDescending(kv => kv.Value)
            .Take(15)
            .ToList();
        if (topAttackers.Count == 0)
        {
            return;
        }

        var totalFailures = _failedByIp.Values.Sum();
        var lines = string.Join("\n",
            topAttackers.Select(kv => $"  {kv.Key,-15}  {kv.Value,6:N0} lần thất bại"));

        ctx.Emit(Finding.Create(
            id: $"{Id}-BRUTE-FORCE",
            title: $"Brute-force SSH lớn: {totalFailures:N0} lần thất bại từ {_failedByIp.Count} IP",
            severity: Severity.High,
            category: "log-forensics.ssh-anomaly",
            asset: $"host:{ctx.MachineName}",
            evidence: $"Tổng số dòng Failed password: {totalFailures:N0}\n"
                    + $"Số IP nguồn duy nhất: {_failedByIp.Count}\n"
                    + $"Top {topAttackers.Count} IP nguy hiểm nhất:\n{lines}",
            remediation: "1) Chặn các IP top-attacker ở firewall/border. "
                       + "2) Cài fail2ban (ngưỡng 5 fails/10 phút → ban 1h). "
                       + "3) Vô hiệu hoá đăng nhập password — chỉ giữ public-key. "
                       + "4) Đổi cổng SSH khỏi 22 nếu hệ thống lộ ra Internet. "
                       + "5) Đối chiếu các IP top-attacker với threat-intel feed.",
            references: BruteForceRefs));
    }

    public void Reset()
    {
        _failedByIp.Clear();
        _publickeyIpsPerUser.Clear();
        _suspiciousPasswordLogins.Clear();
        _emitted.Clear();
    }

    private static bool IsPublicRoutable(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) { return false; }
        if (!byte.TryParse(parts[0], out var a)) { return false; }
        if (!byte.TryParse(parts[1], out var b)) { return false; }
        if (a == 10 || a == 127 || a == 0 || a >= 224) { return false; }
        if (a == 172 && b >= 16 && b <= 31) { return false; }
        if (a == 192 && b == 168) { return false; }
        if (a == 169 && b == 254) { return false; }
        return true;
    }
}
