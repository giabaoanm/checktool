using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Flags privilege-escalation indicators across Windows and Linux:
///   * Windows Event 4672 (Special privileges assigned) for non-service accounts
///     — standard admin-logon signal, noisy but very useful for non-admin users.
///   * Linux <c>sudo COMMAND=</c> for a command not in typical admin allow-list, or
///     preceded by a sudo <c>authentication failure</c> (guess-then-succeed pattern).
///   * Linux bash <c>su -</c> / <c>sudo -i</c> / <c>sudo su</c> — raw shell escalation.
/// </summary>
public sealed class PrivilegeEscalationRule : IDetectionRule
{
    public string Id => "FOR-PRIVESC";
    public string Name => "Leo thang đặc quyền (Privilege escalation)";

    private static readonly string[] ServiceAccounts =
        { "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0", "UMFD-1" };

    /// <summary>
    /// Well-known service-account SIDs. Event 4672 fires every time SYSTEM /
    /// LocalService / NetworkService / IUSR / etc establish a logon session — that
    /// happens thousands of times a day on a normal machine and is pure noise. We
    /// filter by SID directly because the user-friendly name field is sometimes
    /// missing/garbled on Win10/11 evtx (operator at Sơn La saw the rule emit
    /// "Tài khoản (unknown)" for what was really S-1-5-18 / SYSTEM).
    /// </summary>
    private static readonly HashSet<string> ServiceSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",   // LocalSystem (NT AUTHORITY\SYSTEM)
        "S-1-5-19",   // LocalService
        "S-1-5-20",   // NetworkService
        "S-1-5-17",   // IUSR (IIS anonymous)
        "S-1-5-90-0", // Window Manager group (DWM-*)
        "S-1-5-96-0", // Font Driver Host (UMFD-*)
    };

    /// <summary>
    /// Substrings that, when present in the event Raw field, indicate the subject is
    /// a service account regardless of how the User field parsed. Acts as a defence in
    /// depth on top of <see cref="ServiceSids"/>.
    /// </summary>
    private static readonly string[] ServiceRawMarkers =
    {
        "S-1-5-18", "S-1-5-19", "S-1-5-20", "NT AUTHORITY\\SYSTEM",
        "Account Domain:\tNT AUTHORITY",
        "Account Name:\tSYSTEM", "Account Name:\tLOCAL SERVICE", "Account Name:\tNETWORK SERVICE",
    };

    private static readonly string[] SuspiciousSudoCmds =
    {
        "chmod 4755", "chmod u+s", "setcap cap_sys_admin", "visudo",
        "cp /bin/bash", "bash -p", "sh -p", "nsenter", "unshare -r",
        "mknod ", "/tmp/", "curl http", "wget http", "ncat -e", "nc -e"
    };

    private static readonly string[] ShellEscalations =
        { "sudo -i", "sudo su", "su -", "su root", "sudo bash", "sudo /bin/bash" };

    private static readonly string[] ReferencesArr =
    {
        "MITRE ATT&CK T1548 — Abuse Elevation Control Mechanism",
        "MITRE ATT&CK T1068 — Exploitation for Privilege Escalation",
        "Windows Event ID 4672 — Special privileges assigned to new logon"
    };

    private readonly HashSet<string> _recentSudoFailures = new(StringComparer.Ordinal);
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        switch (record.EventKind)
        {
            case "privilege.assigned":
                // Event 4672 ("Special privileges assigned") is baseline Windows
                // telemetry. Every service, scheduled task, RPC logon, and admin token
                // can produce it many times per day, so it must not emit a finding on
                // its own. Correlation chains may still consume the parsed record.
                break;

            case "sudo.failed":
                {
                    var u = record.GetField("TargetUserName");
                    if (!string.IsNullOrEmpty(u)) { _recentSudoFailures.Add(u); }
                    break;
                }

            case "sudo.command":
                HandleSudo(record, ctx);
                break;

            case "bash.command":
                HandleBash(record, ctx);
                break;
        }
    }

    private void HandleWinAdminLogon(LogRecord r, ForensicsContext ctx)
    {
        var user = r.GetField("SubjectUserName") ?? r.GetField("TargetUserName") ?? "(unknown)";
        var sid = r.GetField("SubjectUserSid") ?? r.GetField("TargetUserSid") ?? string.Empty;
        var raw = r.RawLine ?? string.Empty;

        // Skip well-known service accounts via three layers of detection:
        //   (1) SID match — most reliable, survives broken username parsing
        //   (2) friendly-name match — backstop when SID is empty
        //   (3) substring match in raw event text — last-resort for evtx variants
        //       that don't expose either field cleanly. Computer accounts (ending
        //       in '$') are also skipped — those are AD machine accounts logging
        //       onto themselves, not human privilege escalation.
        if (!string.IsNullOrEmpty(sid) && ServiceSids.Contains(sid)) { return; }
        if (Array.Exists(ServiceAccounts, s => s.Equals(user, StringComparison.OrdinalIgnoreCase))) { return; }
        if (user.EndsWith('$')) { return; }
        foreach (var marker in ServiceRawMarkers)
        {
            if (raw.Contains(marker, StringComparison.OrdinalIgnoreCase)) { return; }
        }

        var key = "W:" + user.ToLowerInvariant();
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-W-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Tài khoản {user} được gán đặc quyền quản trị (Event 4672)",
            severity: ctx.IsWhitelistedUser(user) ? Severity.Medium : Severity.High,
            category: "log-forensics.priv-esc",
            asset: $"user:{user}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] Event 4672 Special privileges assigned.\n"
                + $"User={user}\nRaw: {r.RawLine}",
            remediation: "Xác minh tài khoản này có thuộc danh sách admin hợp lệ không."
                + " Nếu không: vô hiệu hoá tài khoản và kiểm tra nhật ký đăng nhập gần đây.",
            references: ReferencesArr));
    }

    private void HandleSudo(LogRecord r, ForensicsContext ctx)
    {
        var cmd = r.GetField("Command") ?? string.Empty;
        var user = r.GetField("SourceUser") ?? "(unknown)";

        bool isSuspicious = false;
        string? matched = null;
        foreach (var s in SuspiciousSudoCmds)
        {
            if (cmd.Contains(s, StringComparison.OrdinalIgnoreCase))
            {
                isSuspicious = true;
                matched = s;
                break;
            }
        }

        bool afterFailure = _recentSudoFailures.Remove(user);
        if (!isSuspicious && !afterFailure) { return; }

        var key = "S:" + user + ":" + (matched ?? "post-fail");
        if (!_emitted.Add(key)) { return; }

        var reasons = new List<string>();
        if (isSuspicious) { reasons.Add($"lệnh nhạy cảm \"{matched}\""); }
        if (afterFailure) { reasons.Add("ngay sau khi authentication failure"); }

        ctx.Emit(Finding.Create(
            id: $"{Id}-S-{Math.Abs(key.GetHashCode()):X8}",
            title: $"sudo đáng ngờ từ {user}",
            severity: Severity.High,
            category: "log-forensics.priv-esc",
            asset: $"user:{user}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] sudo COMMAND={cmd}\nLý do: {string.Join(", ", reasons)}\nRaw: {r.RawLine}",
            remediation: "Rà soát sudoers, kiểm tra có bypass quyền root không. Thu hồi quyền sudo nếu user không còn cần.",
            references: ReferencesArr));
    }

    private void HandleBash(LogRecord r, ForensicsContext ctx)
    {
        var cmd = r.GetField("Command") ?? string.Empty;
        foreach (var s in ShellEscalations)
        {
            if (cmd.Contains(s, StringComparison.OrdinalIgnoreCase))
            {
                var key = "B:" + cmd.ToLowerInvariant();
                if (!_emitted.Add(key)) { return; }
                ctx.Emit(Finding.Create(
                    id: $"{Id}-B-{Math.Abs(key.GetHashCode()):X8}",
                    title: "Lệnh shell leo thang đặc quyền",
                    severity: Severity.Medium,
                    category: "log-forensics.priv-esc",
                    asset: $"host:{ctx.MachineName}",
                    evidence: $"[{r.SourceFile}:{r.SourceOffset}] bash history: {cmd}",
                    remediation: "Xác minh tài khoản có quyền root hợp lệ. Cân nhắc tắt su/sudo bash login cho user thường.",
                    references: ReferencesArr));
                return;
            }
        }
    }

    public void Flush(ForensicsContext ctx) { }

    public void Reset()
    {
        _recentSudoFailures.Clear();
        _emitted.Clear();
    }
}
