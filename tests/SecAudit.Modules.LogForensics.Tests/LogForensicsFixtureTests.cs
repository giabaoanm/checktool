using System.Runtime.Versioning;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Correlation;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Parsers;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Modules.LogForensics.Sources;
using SecAudit.Security;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Runs the full LogForensicsEngine pipeline against hand-crafted fixture log files that
/// embed characteristic attack signatures. Each test verifies ONE detection rule fires
/// (and, where applicable, that benign lines do NOT fire). This doubles as an end-to-end
/// smoke test for the offline audit path — LocalFolderSource is exactly what the CLI
/// <c>--offline</c> mode points at <c>%SystemDrive%\Windows\System32\winevt\Logs</c> with.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LogForensicsFixtureTests
{
    private static string FixturesRoot()
    {
        // tests copy Fixtures\logs\ into the assembly output dir via .csproj Link item.
        var here = AppContext.BaseDirectory;
        var candidate = Path.Combine(here, "Fixtures", "logs");
        if (Directory.Exists(candidate)) { return candidate; }
        // Fallback for `dotnet test` direct runs without copy — walk up to the repo root.
        var dir = new DirectoryInfo(here);
        while (dir is not null)
        {
            var p = Path.Combine(dir.FullName, "tests", "Fixtures", "logs");
            if (Directory.Exists(p)) { return p; }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Cannot locate tests/Fixtures/logs relative to " + here);
    }

    private static async Task<ForensicsResult> RunAsync(string subfolder, string userWhitelist = "")
    {
        var parsers = new ILogParser[]
        {
            new LinuxAuthLogParser(),
            new LinuxSyslogParser(),
            new NginxAccessLogParser(),
            new ApacheErrorLogParser(),
            new IisW3cLogParser(),
            new WindowsEvtxParser(),
            new BashHistoryParser(),
        };
        var rules = new IDetectionRule[]
        {
            new BruteForceRule(),
            new UnknownLogonRule(),
            new BackdoorServiceRule(),
            new LogClearedRule(),
            new VulnScanRule(),
            new PrivilegeEscalationRule(),
            new KeyloggerRule(),
            new RansomwareRule(),
            new DataDestructionRule(),
        };
        var source = new LocalFolderSource();
        var audit = new AuditLog();
        // Empty correlation set — these tests verify individual rules, not chains.
        var correlation = new CorrelationEngine(
            Array.Empty<ICorrelationChain>(),
            NullLogger<CorrelationEngine>.Instance);
        var engine = new LogForensicsEngine(
            parsers,
            rules,
            _ => source,
            correlation,
            audit,
            NullLogger<LogForensicsEngine>.Instance);

        var settings = new ForensicsSettings
        {
            SourceKind = ForensicsSourceKind.LocalFolder,
            LocalPath = Path.Combine(FixturesRoot(), subfolder),
            LocalRecursive = true,
            UserWhitelist = userWhitelist,
            EvidenceRoot = Path.Combine(Path.GetTempPath(), "SecAudit.Tests", Guid.NewGuid().ToString("N")),
        };

        return await engine.RunAsync(settings, new Progress<ForensicsProgress>(_ => { }), CancellationToken.None);
    }

    [Fact]
    public async Task Brute_force_rule_fires_on_repeated_failed_logons()
    {
        var result = await RunAsync("linux");
        result.Findings.Should().Contain(f => f.Category == "log-forensics.brute-force",
            because: "auth.log contains 15 failed passwords for root from 203.0.113.45");
        var brute = result.Findings.Where(f => f.Category == "log-forensics.brute-force").ToList();
        brute.Should().Contain(f => f.Asset == "user:root");
        brute.Should().Contain(f => f.Asset == "ip:203.0.113.45");
    }

    [Fact]
    public async Task Log_cleared_rule_fires_on_rsyslog_restart_marker()
    {
        var result = await RunAsync("linux");
        result.Findings.Should().Contain(f => f.Category == "log-forensics.evidence-tampering",
            because: "auth.log begins with an rsyslogd start line which maps to log.cleared");
    }

    [Fact]
    public async Task Unknown_logon_rule_fires_for_non_whitelisted_user()
    {
        var result = await RunAsync("linux", userWhitelist: "admin,root,dev");
        result.Findings.Should().Contain(f =>
            f.Category == "log-forensics.unknown-logon" && f.Asset == "user:mallory");
        result.Findings.Should().NotContain(f =>
            f.Category == "log-forensics.unknown-logon" && f.Asset == "user:admin");
    }

    [Fact]
    public async Task Unknown_logon_rule_is_silent_when_whitelist_empty()
    {
        var result = await RunAsync("linux");
        result.Findings.Should().NotContain(f => f.Category == "log-forensics.unknown-logon",
            because: "without a baseline whitelist every successful login would be noise");
    }

    [Fact]
    public async Task Priv_esc_rule_fires_on_suspicious_sudo_command()
    {
        var result = await RunAsync("linux");
        result.Findings.Should().Contain(f => f.Category == "log-forensics.priv-esc",
            because: "auth.log has 'sudo ... COMMAND=/bin/bash -p' after an auth failure, "
                + "and bash_history has 'sudo -i'");
    }

    [Fact]
    public async Task Keylogger_rule_fires_on_logkeys_install_command()
    {
        var result = await RunAsync("linux");
        result.Findings.Should().Contain(f =>
            f.Category == "log-forensics.keylogger"
            && f.Title.Contains("keylogger", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Ransomware_rule_fires_on_shadow_copy_deletion()
    {
        var result = await RunAsync("linux");
        result.Findings.Should().Contain(f =>
            f.Category == "log-forensics.ransomware"
            && f.Severity == Severity.Critical,
            because: "bash_history contains 'vssadmin delete shadows /all /quiet'");
    }

    [Fact]
    public async Task Data_destruction_rule_fires_on_wipe_commands()
    {
        var result = await RunAsync("linux");
        var wipes = result.Findings.Where(f => f.Category == "log-forensics.data-destruction").ToList();
        wipes.Should().HaveCountGreaterThanOrEqualTo(2,
            because: "bash_history has 'rm -rf --no-preserve-root /' AND 'dd if=/dev/zero of=/dev/sda'");
        wipes.Should().OnlyContain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public async Task Vuln_scan_rule_fires_on_scanner_user_agent()
    {
        var result = await RunAsync("web");
        result.Findings.Should().Contain(f =>
            f.Category == "log-forensics.vuln-scan"
            && f.Asset == "ip:203.0.113.99",
            because: "access.log contains a request with sqlmap User-Agent");
    }

    [Fact]
    public async Task Vuln_scan_rule_fires_on_url_fan_out()
    {
        var result = await RunAsync("web");
        result.Findings.Should().Contain(f =>
            f.Category == "log-forensics.vuln-scan"
            && f.Asset == "ip:198.51.100.77",
            because: "access.log contains 55 distinct URIs from that IP within 60s");
    }

    [Fact]
    public async Task Engine_produces_manifest_with_evidence_hashes()
    {
        var result = await RunAsync("linux");
        result.TotalFiles.Should().BeGreaterThan(0);
        result.Manifest.Should().OnlyContain(e => e.Sha256.Length == 64,
            because: "LocalFolderSource hashes every file up-front for chain of custody");
        File.Exists(Path.Combine(result.EvidenceRoot, "manifest.json")).Should().BeTrue();
    }
}
