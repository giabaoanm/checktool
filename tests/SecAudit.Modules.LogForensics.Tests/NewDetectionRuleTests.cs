using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.LinuxIncident;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Targeted tests for the rule expansions and false-positive fix shipped to address
/// the SOC analyst feedback that the previous version flagged <c>rm -rf /tmp/.crond</c>
/// as full-disk wipe and missed the actual SSH-password-login smoking gun.
/// </summary>
public sealed class NewDetectionRuleTests
{
    private static LogRecord MakeBashCmd(string command, string srcFile = "auth.log", int line = 1)
        => new()
        {
            Timestamp = DateTimeOffset.UtcNow,
            SourceFile = srcFile,
            SourceOffset = line,
            Os = "linux",
            EventKind = "sudo.command",
            RawLine = "sudo: " + command,
            Fields = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Command"] = command,
                ["SourceUser"] = "victim"
            }
        };

    private static LogRecord MakeSsh(string kind, string ip, string user = "victim", string method = "password")
        => new()
        {
            Timestamp = DateTimeOffset.UtcNow,
            SourceFile = "auth.log",
            SourceOffset = 1,
            Os = "linux",
            EventKind = kind,
            RawLine = $"sshd: {kind} from {ip} user {user}",
            Fields = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["IpAddress"] = ip,
                ["TargetUserName"] = user,
                ["Method"] = method
            }
        };

    private static ForensicsContext NewCtx() => new()
    {
        UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        InternalCidrs = Array.Empty<CidrRange>(),
        MachineName = "HOST-TEST"
    };

    [Fact]
    public void DataDestructionRule_does_NOT_fire_on_rm_rf_tmp_subpath()
    {
        var rule = new DataDestructionRule();
        var ctx = NewCtx();

        rule.Observe(MakeBashCmd("/usr/bin/rm -rf /tmp/.crond"), ctx);
        rule.Observe(MakeBashCmd("/usr/bin/rm -rf /var/cache/apt/archives/"), ctx);
        rule.Observe(MakeBashCmd("rm -rf /home/foo/.cache/"), ctx);

        ctx.Findings.Should().NotContain(f => f.Id.StartsWith("FOR-WIPE-"),
            "cleanup of /tmp / /var/cache / user .cache must NOT be classified as data destruction");
    }

    [Fact]
    public void DataDestructionRule_DOES_fire_on_real_root_wipe()
    {
        var rule = new DataDestructionRule();
        var ctx = NewCtx();

        rule.Observe(MakeBashCmd("rm -rf / --no-preserve-root"), ctx);

        ctx.Findings.Should().Contain(f => f.Id.StartsWith("FOR-WIPE-")
            && f.Severity == Severity.Critical);
    }

    [Fact]
    public void DataDestructionRule_fires_on_top_level_system_dir_wipe()
    {
        var rule = new DataDestructionRule();
        var ctx = NewCtx();

        rule.Observe(MakeBashCmd("rm -rf /etc"), ctx);

        ctx.Findings.Should().Contain(f => f.Id.StartsWith("FOR-WIPE-"));
    }

    [Fact]
    public void PrivescRule_fires_on_chmod_executable_in_system_path()
    {
        var rule = new PrivilegeEscalationRule();
        var ctx = NewCtx();

        rule.Observe(MakeBashCmd("/usr/bin/chmod +x /usr/local/bin/.crond"), ctx);

        ctx.Findings.Should().Contain(f => f.Id.StartsWith("FOR-PRIVESC-S-")
            && f.Evidence.Contains("chmod"));
    }

    [Fact]
    public void PrivescRule_fires_on_encrypt_flag()
    {
        var rule = new PrivilegeEscalationRule();
        var ctx = NewCtx();

        rule.Observe(MakeBashCmd("/usr/local/bin/.crond --encrypt /home/victim/Documents/"), ctx);

        ctx.Findings.Should().Contain(f => f.Id.StartsWith("FOR-PRIVESC-S-"));
    }

    [Fact]
    public void PrivescRule_fires_on_hidden_binary_in_usr_local_bin()
    {
        var rule = new PrivilegeEscalationRule();
        var ctx = NewCtx();

        rule.Observe(MakeBashCmd("/usr/local/bin/.daemon --beacon"), ctx);

        ctx.Findings.Should().Contain(f => f.Id.StartsWith("FOR-PRIVESC-S-"));
    }

    [Fact]
    public void SshAnomalyRule_fires_on_password_login_after_brute_force()
    {
        var rule = new SshLoginAnomalyRule();
        var ctx = NewCtx();

        for (var i = 0; i < 10; i++)
        {
            rule.Observe(MakeSsh("logon.failed", "89.187.163.211"), ctx);
        }
        rule.Observe(MakeSsh("logon.success", "89.187.163.211", method: "password"), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-SSH-ANOMALY-ACCEPT-")
            && f.Severity == Severity.Critical
            && f.Evidence.Contains("89.187.163.211"));
    }

    [Fact]
    public void SshAnomalyRule_fires_on_password_login_when_user_normally_uses_publickey()
    {
        var rule = new SshLoginAnomalyRule();
        var ctx = NewCtx();

        rule.Observe(MakeSsh("logon.success", "10.0.2.10", method: "publickey"), ctx);
        rule.Observe(MakeSsh("logon.success", "89.187.163.211", method: "password"), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-SSH-ANOMALY-ACCEPT-"));
    }

    [Fact]
    public void SshAnomalyRule_emits_brute_force_summary_at_flush()
    {
        var rule = new SshLoginAnomalyRule();
        var ctx = NewCtx();

        // 150 failures from one IP, 110 from another — both above the 100-threshold.
        for (var i = 0; i < 150; i++) { rule.Observe(MakeSsh("logon.failed", "89.187.163.211"), ctx); }
        for (var i = 0; i < 110; i++) { rule.Observe(MakeSsh("logon.failed", "45.95.168.191"), ctx); }
        rule.Flush(ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id == "FOR-SSH-ANOMALY-BRUTE-FORCE"
            && f.Evidence.Contains("89.187.163.211")
            && f.Evidence.Contains("45.95.168.191"));
    }

    [Fact]
    public void SshAnomalyRule_skips_RFC1918_internal_traffic()
    {
        var rule = new SshLoginAnomalyRule();
        var ctx = NewCtx();

        for (var i = 0; i < 200; i++) { rule.Observe(MakeSsh("logon.failed", "10.0.2.10"), ctx); }
        rule.Flush(ctx);

        ctx.Findings.Should().BeEmpty(
            "internal lateral-movement traffic does not count as Internet brute force");
    }

    [Fact]
    public void PdfWriter_renders_non_empty_pdf_byte_array()
    {
        var ar = new LinuxIncidentAnalyzer.AnalysisResult(
            new[]
            {
                Finding.Create(
                    id: "LIN-RANSOM-NOTE-X",
                    title: "Ransom note",
                    severity: Severity.Critical,
                    category: "linux",
                    asset: "DAVE",
                    evidence: "Sample evidence line\nwith newline",
                    remediation: "Cô lập máy, không trả tiền chuộc.",
                    attackTechniques: new[] { "T1486" })
            },
            FilesScanned: 5,
            ExtractedIocs: new[] { "btc:bc1qxy", "email:phantom@example.test", "ip:1.2.3.4" },
            ExtractedOciTempDir: null);

        var ctx = new LinuxIncidentReportBuilder.ReportContext(
            "DAVE", "/tmp/x", DateTimeOffset.UtcNow, ar);

        var pdf = LinuxIncidentPdfWriter.Render(ctx);

        pdf.Length.Should().BeGreaterThan(2000);
        // PDF magic bytes: %PDF
        pdf[0].Should().Be((byte)'%');
        pdf[1].Should().Be((byte)'P');
        pdf[2].Should().Be((byte)'D');
        pdf[3].Should().Be((byte)'F');
    }
}
