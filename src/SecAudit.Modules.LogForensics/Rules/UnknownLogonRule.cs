using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Flags successful logons where the account name is not in the user-supplied whitelist.
/// A successful logon is much more impactful than a failed one — one hit = one finding.
/// Ignored if the whitelist is empty (user didn't configure baseline).
/// </summary>
public sealed class UnknownLogonRule : IDetectionRule
{
    public string Id => "FOR-UNKNOWN";
    public string Name => "Đăng nhập bằng tài khoản lạ";

    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] ReferencesArr =
    {
        "Windows Event ID 4624",
        "MITRE ATT&CK T1078 — Valid Accounts"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        var r = record;
        if (r.EventKind != "logon.success" && r.EventKind != "logon.explicit") { return; }
        if (ctx.UserWhitelist.Count == 0) { return; }

        var user = r.GetField("TargetUserName");
        if (string.IsNullOrWhiteSpace(user)) { return; }
        if (IsSystemAccount(user!)) { return; }
        if (ctx.IsWhitelistedUser(user)) { return; }

        var ip = r.GetField("IpAddress") ?? "(local)";
        var logonType = r.GetField("LogonType") ?? r.GetField("Method") ?? "?";
        var key = $"{user!.ToLowerInvariant()}|{ip}";
        if (!_seen.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Đăng nhập thành công bằng tài khoản lạ: \"{user}\" từ {ip}",
            severity: ctx.IsInternalIp(ip == "(local)" ? null : ip) ? Severity.High : Severity.Critical,
            category: "log-forensics.unknown-logon",
            asset: $"user:{user}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] {r.RawLine}\n"
                + $"LogonType={logonType}, IP={ip}, Timestamp={r.Timestamp:u}",
            remediation: "Xác minh xem tài khoản này có được phép hay không; nếu không, vô hiệu hoá"
                + " ngay và rà soát hoạt động của tài khoản.",
            references: ReferencesArr));
    }

    private static bool IsSystemAccount(string user)
    {
        if (user.EndsWith('$')) { return true; } // machine account
        return user.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
            || user.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase)
            || user.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase)
            || user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)
            || user.Equals("DWM-1", StringComparison.OrdinalIgnoreCase)
            || user.Equals("UMFD-0", StringComparison.OrdinalIgnoreCase)
            || user.Equals("UMFD-1", StringComparison.OrdinalIgnoreCase);
    }

    public void Flush(ForensicsContext ctx) { }

    public void Reset() => _seen.Clear();
}
