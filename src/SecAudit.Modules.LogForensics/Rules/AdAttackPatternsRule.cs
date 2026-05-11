using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects four classic Active Directory attack patterns from Windows Security
/// EVTX events. These are post-foothold techniques attackers use once they have
/// any valid AD credential — they're invisible to ordinary brute-force / privilege
/// rules but produce specific signatures in Kerberos and DS audit events:
///
/// <list type="number">
///   <item><b>Kerberoasting</b> (T1558.003) — attacker requests service tickets
///         (TGS) for service accounts using legacy RC4-HMAC encryption type
///         (<c>TicketEncryptionType=0x17</c>) so the ticket can be cracked
///         offline. We flag any 4769 with RC4 + non-machine target. Crowdsourced
///         threshold: ≥3 distinct service names from one user in &lt;1 hour =
///         High confidence Kerberoasting.</item>
///   <item><b>AS-REP roasting</b> (T1558.004) — attacker requests TGT (4768)
///         for accounts with pre-authentication disabled
///         (<c>TicketOptions</c> 0x40810010 + bit 0x40 NOT set) and cracks the
///         response offline. Less common but produces unmistakable 4768 with
///         the no-preauth flag.</item>
///   <item><b>DCSync</b> (T1003.006) — attacker abuses Replicating Directory
///         Changes permission to pull NTDS.dit hashes. Signature: 4662 with
///         <c>Properties</c> containing GUID
///         <c>{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}</c> (DS-Replication-Get-Changes)
///         from a non-DC source.</item>
///   <item><b>Zerologon residue</b> (T1068 / CVE-2020-1472) — attacker resets
///         the DC's machine account password to all zeros. Signature: 4742
///         (computer account changed) where the target ends in <c>$</c>
///         (machine account) and the source IP is internal-but-unusual.</item>
/// </list>
/// </summary>
public sealed class AdAttackPatternsRule : IDetectionRule
{
    public string Id => "FOR-AD-ATTACK";
    public string Name => "AD attack patterns (Kerberoasting / AS-REP / DCSync / Zerologon)";

    private const string DcSyncReplicationGuid = "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}";
    private const string DcSyncReplicationGuidAlt = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"; // no braces

    // Kerberoasting threshold: how many distinct SPNs one user must request via RC4
    // within the run window before we emit a finding (single one is suspicious only
    // if it's a high-value SPN; multiple is unmistakable enumeration).
    private const int KerberoastSpnThreshold = 3;

    private static readonly string[] KerberoastRefs =
    {
        "MITRE ATT&CK T1558.003 — Kerberoasting",
        "MITRE ATT&CK T1110 — Brute Force"
    };

    private static readonly string[] AsRepRefs =
    {
        "MITRE ATT&CK T1558.004 — AS-REP Roasting"
    };

    private static readonly string[] DcSyncRefs =
    {
        "MITRE ATT&CK T1003.006 — OS Credential Dumping: DCSync",
        "MITRE ATT&CK T1003 — OS Credential Dumping"
    };

    private static readonly string[] ZerologonRefs =
    {
        "MITRE ATT&CK T1068 — Exploitation for Privilege Escalation",
        "CVE-2020-1472 — Netlogon Elevation of Privilege (Zerologon)"
    };

    /// <summary>Per-user set of SPNs they've requested via RC4 (Kerberoasting candidate).</summary>
    private readonly Dictionary<string, HashSet<string>> _rc4SpnsByUser = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(ctx);

        switch (record.EventKind)
        {
            case "kerberos.tgs.request":
                CheckKerberoasting(record, ctx);
                break;
            case "kerberos.tgt.request":
                CheckAsRepRoasting(record, ctx);
                break;
            case "directory.object.access":
                CheckDcSync(record, ctx);
                break;
            case "computer.changed":
                CheckZerologonResidue(record, ctx);
                break;
        }
    }

    // -----------------------------------------------------------------
    //  1. Kerberoasting (4769 + TicketEncryptionType=0x17 RC4)
    // -----------------------------------------------------------------

    private void CheckKerberoasting(LogRecord r, ForensicsContext ctx)
    {
        var encType = NormalizeEncType(r.GetField("TicketEncryptionType") ?? string.Empty);
        // 0x17 = RC4-HMAC (legacy, Kerberoasting target)
        // 0xFFFFFFFF appears on failed requests — ignore those.
        if (encType != "0x17") { return; }

        var user = r.GetField("TargetUserName") ?? string.Empty;
        var spn = r.GetField("ServiceName") ?? string.Empty;
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(spn)) { return; }
        // Skip legitimate machine-to-service tickets (machine accounts end in $)
        if (user.EndsWith('$') || spn.EndsWith('$')) { return; }
        // krbtgt itself isn't a valid roast target
        if (spn.Equals("krbtgt", StringComparison.OrdinalIgnoreCase)) { return; }

        if (!_rc4SpnsByUser.TryGetValue(user, out var set))
        {
            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _rc4SpnsByUser[user] = set;
        }
        set.Add(spn);

        // Emit at threshold. Subsequent matches don't re-emit (key in _emitted).
        if (set.Count < KerberoastSpnThreshold) { return; }

        var key = "KRBROAST:" + user;
        if (!_emitted.Add(key)) { return; }

        var spnList = string.Join(", ", set.Take(10));
        ctx.Emit(Finding.Create(
            id: $"{Id}-KRBROAST-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Nghi vấn Kerberoasting: user '{user}' yêu cầu {set.Count} TGS RC4-HMAC khác nhau",
            severity: Severity.High,
            category: "log-forensics.ad-attack",
            asset: $"user:{user}",
            evidence: $"User: {user}\n"
                    + $"Số SPN khác nhau đã request RC4-HMAC: {set.Count}\n"
                    + $"Top SPN: {spnList}\n"
                    + $"Encryption type: 0x17 (RC4-HMAC, legacy — bị Kerberoasting tool ưu tiên)\n"
                    + $"Sự kiện gần nhất: [{r.SourceFile}:{r.SourceOffset}] {r.RawLine}",
            remediation: "1) Đặt service account sang AES-only (UF_DONT_REQUIRE_PREAUTH=False, "
                       + "UseAesKeys ở GPO). "
                       + "2) Đổi password mọi service account đang dùng RC4 với mật khẩu ≥25 ký tự "
                       + "(crack RC4 yếu khi password ngắn). "
                       + "3) Theo dõi event 4769 RC4 trong SIEM với baseline. "
                       + "4) Kiểm tra workstation user gốc xem có bị compromise (mimikatz / Rubeus).",
            references: KerberoastRefs));
    }

    private static string NormalizeEncType(string raw)
    {
        if (string.IsNullOrEmpty(raw)) { return string.Empty; }
        var s = raw.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { return s.ToLowerInvariant(); }
        // Some EVTX expose decimal — convert to hex form for comparison.
        if (int.TryParse(s, out var n)) { return "0x" + n.ToString("x"); }
        return s.ToLowerInvariant();
    }

    // -----------------------------------------------------------------
    //  2. AS-REP roasting (4768 + pre-auth disabled)
    // -----------------------------------------------------------------

    private void CheckAsRepRoasting(LogRecord r, ForensicsContext ctx)
    {
        var encType = NormalizeEncType(r.GetField("TicketEncryptionType") ?? string.Empty);
        if (encType != "0x17") { return; } // Only RC4 TGT is roastable

        var ticketOptions = r.GetField("TicketOptions") ?? string.Empty;
        // TicketOptions is a hex bitfield. Bit 0x40 = "renewable"; absence of pre-auth
        // flag manifests in the PreAuthType field below — both are required signals.
        var preAuthType = r.GetField("PreAuthType") ?? string.Empty;
        // PreAuthType=0 means NO pre-authentication was performed → account is roastable.
        if (preAuthType.Trim() != "0") { return; }

        var user = r.GetField("TargetUserName") ?? string.Empty;
        if (string.IsNullOrEmpty(user) || user.EndsWith('$')
            || user.Equals("krbtgt", StringComparison.OrdinalIgnoreCase)) { return; }

        var key = "ASREP:" + user;
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-ASREP-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Nghi vấn AS-REP Roasting: TGT cho '{user}' không pre-auth, encryption RC4",
            severity: Severity.High,
            category: "log-forensics.ad-attack",
            asset: $"user:{user}",
            evidence: $"User: {user}\n"
                    + $"PreAuthType: {preAuthType} (0 = pre-authentication TẮT)\n"
                    + $"TicketEncryptionType: 0x17 (RC4-HMAC)\n"
                    + $"TicketOptions: {ticketOptions}\n"
                    + $"Sự kiện: [{r.SourceFile}:{r.SourceOffset}] {r.RawLine}",
            remediation: "1) Bật yêu cầu pre-authentication cho mọi user account (UAC flag "
                       + "DONT_REQ_PREAUTH = false). "
                       + "2) Đổi password user này nếu xác nhận credential đã bị crack. "
                       + "3) Soát mọi account khác trong domain xem còn account nào bị disable pre-auth.",
            references: AsRepRefs));
    }

    // -----------------------------------------------------------------
    //  3. DCSync (4662 + Replicating Directory Changes GUID)
    // -----------------------------------------------------------------

    private void CheckDcSync(LogRecord r, ForensicsContext ctx)
    {
        var properties = r.GetField("Properties") ?? string.Empty;
        if (string.IsNullOrEmpty(properties)) { return; }

        if (!properties.Contains(DcSyncReplicationGuid, StringComparison.OrdinalIgnoreCase)
            && !properties.Contains(DcSyncReplicationGuidAlt, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var user = r.GetField("SubjectUserName") ?? string.Empty;
        // Skip legitimate DC service accounts (MSOL_*, NT AUTHORITY\*, machine accounts $)
        if (user.EndsWith('$')
            || user.StartsWith("MSOL_", StringComparison.OrdinalIgnoreCase)
            || user.Contains("NT AUTHORITY", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var key = "DCSYNC:" + user;
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-DCSYNC-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Nghi vấn DCSync: user '{user}' yêu cầu replication directory changes",
            severity: Severity.Critical,
            category: "log-forensics.ad-attack",
            asset: $"user:{user}",
            evidence: $"User chủ thể: {user}\n"
                    + $"Properties chứa GUID Replicating-Directory-Changes ({DcSyncReplicationGuid})\n"
                    + $"Đây là quyền chỉ DC + admin có quyền dùng. Một user thường KHÔNG được dùng.\n"
                    + $"Sự kiện: [{r.SourceFile}:{r.SourceOffset}] {r.RawLine}",
            remediation: "1) Cô lập tài khoản này ngay — coi như đã chiếm Domain Admin. "
                       + "2) Reset password krbtgt 2 lần (cách nhau 24h) để invalidate Golden Ticket. "
                       + "3) Soát mọi account đã đăng nhập trong 30 ngày qua + force re-auth. "
                       + "4) Audit ACL trên domain naming context: kiểm tra ai có "
                       + "Replicating-Directory-Changes / Replicating-Directory-Changes-All. "
                       + "5) Kích hoạt audit Directory Service Access đầy đủ nếu chưa.",
            references: DcSyncRefs));
    }

    // -----------------------------------------------------------------
    //  4. Zerologon residue (4742 + machine account password reset)
    // -----------------------------------------------------------------

    private void CheckZerologonResidue(LogRecord r, ForensicsContext ctx)
    {
        var target = r.GetField("TargetUserName") ?? string.Empty;
        // Must be a machine account (ends in $)
        if (!target.EndsWith('$')) { return; }

        var subject = r.GetField("SubjectUserName") ?? string.Empty;
        // Zerologon: subject is ANONYMOUS LOGON or empty (the exploit uses null session)
        var isAnonymous = subject.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrEmpty(subject)
            || subject.Equals("-", StringComparison.Ordinal);
        if (!isAnonymous) { return; }

        // Password change happened: PasswordLastSet field changed OR PWD_LAST_SET attribute audit
        var pwdSet = r.GetField("PasswordLastSet") ?? r.GetField("OldPwdLastSet") ?? string.Empty;
        if (string.IsNullOrEmpty(pwdSet)) { return; }

        var key = "ZEROLOGON:" + target;
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-ZEROLOGON-{Math.Abs(key.GetHashCode()):X8}",
            title: $"Nghi vấn Zerologon (CVE-2020-1472): machine account '{target}' bị đổi mật khẩu bởi ANONYMOUS LOGON",
            severity: Severity.Critical,
            category: "log-forensics.ad-attack",
            asset: $"computer:{target}",
            evidence: $"Machine account: {target}\n"
                    + $"Subject (kẻ thực hiện): {subject} (anonymous)\n"
                    + $"PasswordLastSet: {pwdSet}\n"
                    + $"Sự kiện: [{r.SourceFile}:{r.SourceOffset}] {r.RawLine}",
            remediation: "1) Patch ngay (KB4565351 / cập nhật sau 11/2020 đã default-fix). "
                       + "2) Bắt buộc Netlogon enforcement mode qua HKLM\\SYSTEM\\CCS\\Services\\Netlogon\\"
                       + "Parameters\\FullSecureChannelProtection=1. "
                       + "3) Thay đổi mật khẩu machine account của DC ngay nếu chưa làm sau exploit. "
                       + "4) Block giao thức Netlogon từ internal-untrusted segments.",
            references: ZerologonRefs));
    }

    public void Flush(ForensicsContext ctx) { }

    public void Reset()
    {
        _rc4SpnsByUser.Clear();
        _emitted.Clear();
    }
}
