using System.Text;
using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Tests for the ransomware-precursor rule. Command strings are stored as base64
/// constants and decoded at runtime so the compiled test DLL contains zero literal
/// attack strings — keeps Windows Defender from quarantining the test assembly.
/// </summary>
public sealed class RansomwarePrecursorRuleTests
{
    private static ForensicsContext NewCtx() => new()
    {
        UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        InternalCidrs = Array.Empty<CidrRange>(),
        MachineName = "VICTIM-PC"
    };

    private static string D(string base64) => Encoding.UTF8.GetString(Convert.FromBase64String(base64));

    private static LogRecord MakeProcCmd(string command)
        => new()
        {
            Timestamp = DateTimeOffset.UtcNow,
            SourceFile = "Security.evtx",
            SourceOffset = 1,
            Os = "windows",
            EventKind = "process.created",
            RawLine = command,
            Fields = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["CommandLine"] = command
            }
        };

    [Fact]
    public void Rule_fires_on_safeboot_bcdedit()
    {
        // bcdedit /set {default} safeboot minimal
        var cmd = D("YmNkZWRpdCAvc2V0IHtkZWZhdWx0fSBzYWZlYm9vdCBtaW5pbWFs");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.High);
    }

    [Fact]
    public void Rule_fires_on_wbadmin_delete_backup()
    {
        // wbadmin delete backup -keepVersions:0 -quiet
        var cmd = D("d2JhZG1pbiBkZWxldGUgYmFja3VwIC1rZWVwVmVyc2lvbnM6MCAtcXVpZXQ=");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Rule_fires_on_defender_realtime_disable()
    {
        // Set-MpPreference -DisableRealtimeMonitoring $true
        var cmd = D("U2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZQ==");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Rule_fires_on_taskkill_av_engine()
    {
        // taskkill /F /IM MsMpEng.exe
        var cmd = D("dGFza2tpbGwgL0YgL0lNIE1zTXBFbmcuZXhl");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Rule_fires_on_sql_service_stop()
    {
        // net stop MSSQLSERVER /Y
        var cmd = D("bmV0IHN0b3AgTVNTUUxTRVJWRVIgL1k=");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.High);
    }

    [Fact]
    public void Rule_fires_on_security_event_log_clear()
    {
        // wevtutil cl Security /q:true
        var cmd = D("d2V2dHV0aWwgY2wgU2VjdXJpdHkgL3E6dHJ1ZQ==");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Whitespace_normalisation_lets_double_spaced_command_match()
    {
        // net   stop    WinDefend  (multiple spaces)
        var cmd = D("bmV0ICAgc3RvcCAgICBXaW5EZWZlbmQ=");
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd), ctx);
        ctx.Findings.Should().Contain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Same_marker_emits_only_once_per_run()
    {
        var cmd1 = D("d2V2dHV0aWwgY2wgU2VjdXJpdHkgL3E6dHJ1ZQ=="); // wevtutil cl Security /q:true
        var cmd2 = D("d2V2dHV0aWwgY2wgU2VjdXJpdHk=");             // wevtutil cl Security
        var cmd3 = D("d2V2dHV0aWwgY2wgU2VjdXJpdHkgL3F1aWV0");      // wevtutil cl Security /quiet
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd(cmd1), ctx);
        rule.Observe(MakeProcCmd(cmd2), ctx);
        rule.Observe(MakeProcCmd(cmd3), ctx);

        ctx.Findings.Where(f => f.Id.StartsWith("FOR-RANSOM-PRE-"))
            .Should().HaveCount(1);
    }

    [Fact]
    public void Benign_admin_commands_produce_no_finding()
    {
        var rule = new RansomwarePrecursorRule();
        var ctx = NewCtx();
        rule.Observe(MakeProcCmd("notepad.exe report.txt"), ctx);
        rule.Observe(MakeProcCmd("ipconfig /all"), ctx);
        rule.Observe(MakeProcCmd("net stop spooler"), ctx);
        ctx.Findings.Should().BeEmpty();
    }
}
