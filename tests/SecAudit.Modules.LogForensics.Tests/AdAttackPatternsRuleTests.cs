using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class AdAttackPatternsRuleTests
{
    private static ForensicsContext NewCtx() => new()
    {
        UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        InternalCidrs = Array.Empty<CidrRange>(),
        MachineName = "DC01"
    };

    private static LogRecord MakeEvt(string kind, params (string K, string V)[] fields)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in fields) { dict[k] = v; }
        return new LogRecord
        {
            Timestamp = DateTimeOffset.UtcNow,
            SourceFile = "Security.evtx",
            SourceOffset = 1,
            Os = "windows",
            EventKind = kind,
            RawLine = $"<Event>{kind}</Event>",
            Fields = dict
        };
    }

    // ----- Kerberoasting -----

    [Fact]
    public void Kerberoasting_fires_when_user_requests_3_RC4_TGS_for_distinct_SPNs()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        for (var i = 1; i <= 3; i++)
        {
            rule.Observe(MakeEvt("kerberos.tgs.request",
                ("TargetUserName", "alice"),
                ("ServiceName", $"MSSQLSvc/sql0{i}.contoso.local"),
                ("TicketEncryptionType", "0x17")), ctx);
        }

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-AD-ATTACK-KRBROAST-")
            && f.Severity == Severity.High
            && f.Title.Contains("alice", StringComparison.Ordinal));
    }

    [Fact]
    public void Kerberoasting_does_NOT_fire_for_AES_encryption()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        for (var i = 1; i <= 5; i++)
        {
            rule.Observe(MakeEvt("kerberos.tgs.request",
                ("TargetUserName", "alice"),
                ("ServiceName", $"MSSQLSvc/sql0{i}.contoso.local"),
                ("TicketEncryptionType", "0x12")), ctx); // AES256
        }

        ctx.Findings.Where(f => f.Id.StartsWith("FOR-AD-ATTACK-KRBROAST-"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Kerberoasting_skips_machine_account_targets()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        for (var i = 1; i <= 5; i++)
        {
            rule.Observe(MakeEvt("kerberos.tgs.request",
                ("TargetUserName", "DC01$"), // machine account
                ("ServiceName", $"host/sql0{i}.contoso.local"),
                ("TicketEncryptionType", "0x17")), ctx);
        }

        ctx.Findings.Should().BeEmpty();
    }

    // ----- AS-REP Roasting -----

    [Fact]
    public void AsRep_fires_when_TGT_request_has_no_preauth_and_RC4()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        rule.Observe(MakeEvt("kerberos.tgt.request",
            ("TargetUserName", "svc-legacy"),
            ("PreAuthType", "0"),                   // no pre-auth
            ("TicketEncryptionType", "0x17"),       // RC4
            ("TicketOptions", "0x40810010")), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-AD-ATTACK-ASREP-")
            && f.Severity == Severity.High
            && f.Evidence.Contains("PreAuthType: 0", StringComparison.Ordinal));
    }

    [Fact]
    public void AsRep_does_NOT_fire_when_preauth_is_enabled()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        rule.Observe(MakeEvt("kerberos.tgt.request",
            ("TargetUserName", "alice"),
            ("PreAuthType", "2"),               // ENC_TIMESTAMP — pre-auth used
            ("TicketEncryptionType", "0x17")), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ----- DCSync -----

    [Fact]
    public void DcSync_fires_on_replication_GUID_in_object_access()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        rule.Observe(MakeEvt("directory.object.access",
            ("SubjectUserName", "alice"),
            ("Properties", "Replicating Directory Changes "
                + "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} %{91e647de-d96f-4b70-9557-d63ff4f3ccd8}")), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-AD-ATTACK-DCSYNC-")
            && f.Severity == Severity.Critical);
    }

    [Fact]
    public void DcSync_skips_machine_and_service_accounts()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        rule.Observe(MakeEvt("directory.object.access",
            ("SubjectUserName", "DC01$"),
            ("Properties", "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}")), ctx);
        rule.Observe(MakeEvt("directory.object.access",
            ("SubjectUserName", "MSOL_abc123"),
            ("Properties", "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}")), ctx);

        ctx.Findings.Should().BeEmpty(
            "machine accounts + Azure AD Sync (MSOL_*) legitimately replicate");
    }

    // ----- Zerologon residue -----

    [Fact]
    public void Zerologon_fires_when_machine_account_pwd_changed_by_anonymous_logon()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        rule.Observe(MakeEvt("computer.changed",
            ("TargetUserName", "DC01$"),
            ("SubjectUserName", "ANONYMOUS LOGON"),
            ("PasswordLastSet", "2026-05-10T10:00:00Z")), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-AD-ATTACK-ZEROLOGON-")
            && f.Severity == Severity.Critical
            && f.Title.Contains("DC01$", StringComparison.Ordinal));
    }

    [Fact]
    public void Zerologon_does_NOT_fire_when_legitimate_admin_changed_account()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        rule.Observe(MakeEvt("computer.changed",
            ("TargetUserName", "DC01$"),
            ("SubjectUserName", "Administrator"),
            ("PasswordLastSet", "2026-05-10T10:00:00Z")), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    [Fact]
    public void Each_attack_pattern_emits_only_once_per_user_per_run()
    {
        var rule = new AdAttackPatternsRule();
        var ctx = NewCtx();

        // Trigger Kerberoasting twice for same user (5 SPNs, then 5 more)
        for (var i = 1; i <= 10; i++)
        {
            rule.Observe(MakeEvt("kerberos.tgs.request",
                ("TargetUserName", "alice"),
                ("ServiceName", $"MSSQLSvc/sql{i:D2}"),
                ("TicketEncryptionType", "0x17")), ctx);
        }

        ctx.Findings.Where(f => f.Id.StartsWith("FOR-AD-ATTACK-KRBROAST-"))
            .Should().HaveCount(1, "deduplication via _emitted prevents finding spam");
    }
}
