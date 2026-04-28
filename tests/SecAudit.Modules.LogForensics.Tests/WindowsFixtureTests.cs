using System.Runtime.Versioning;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Correlation;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Parsers;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Rules.Sysmon;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Modules.LogForensics.Sources;
using SecAudit.Security;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// End-to-end fixture tests that exercise <see cref="WindowsEventXmlParser"/> against
/// hand-crafted wevtutil-style XML log fixtures under tests/Fixtures/logs/windows/.
/// Every one of the 10 Sysmon rules, the 2 Security-log rules (FOR-SVC, FOR-CLEAR),
/// and the <c>CHAIN-CREDACCESS</c> correlation chain is verified end-to-end through
/// the real <see cref="LogForensicsEngine"/> pipeline.
///
/// <para>
/// Why XML fixtures instead of <c>.evtx</c>? EVTX is a proprietary binary format that
/// cannot be hand-authored; wevtutil XML export is the documented interchange format
/// and is what SOCs paste into ticketing systems anyway, so fixtures double as
/// ready-to-share IOC bundles.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFixtureTests
{
    private static string FixturesRoot()
    {
        var here = AppContext.BaseDirectory;
        var candidate = Path.Combine(here, "Fixtures", "logs");
        if (Directory.Exists(candidate)) { return candidate; }
        var dir = new DirectoryInfo(here);
        while (dir is not null)
        {
            var p = Path.Combine(dir.FullName, "tests", "Fixtures", "logs");
            if (Directory.Exists(p)) { return p; }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Cannot locate tests/Fixtures/logs relative to " + here);
    }

    /// <summary>
    /// Run the engine against exactly ONE fixture file (the engine still scans the
    /// folder, so we point it at a freshly-copied scratch dir holding only that file
    /// — this keeps each test hermetic and avoids cross-contamination between rules).
    /// </summary>
    private static async Task<ForensicsResult> RunSingleFixtureAsync(
        string fixtureFileName,
        bool withCorrelation = false)
    {
        var src = Path.Combine(FixturesRoot(), "windows", fixtureFileName);
        File.Exists(src).Should().BeTrue($"fixture {fixtureFileName} must exist");

        var scratch = Path.Combine(Path.GetTempPath(), "SecAudit.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        var dest = Path.Combine(scratch, fixtureFileName);
        File.Copy(src, dest);

        var parsers = new ILogParser[]
        {
            new WindowsEventXmlParser(),
            new LinuxAuthLogParser(),
            new LinuxSyslogParser(),
            new NginxAccessLogParser(),
            new ApacheErrorLogParser(),
            new IisW3cLogParser(),
            new BashHistoryParser(),
        };
        var rules = new IDetectionRule[]
        {
            // Security log rules (4625 / 1102 / 7045 / 4688 / 4720 / 4732 / 4104…)
            new BruteForceRule(),
            new UnknownLogonRule(),
            new BackdoorServiceRule(),
            new LogClearedRule(),
            new VulnScanRule(),
            new PrivilegeEscalationRule(),
            new KeyloggerRule(),
            new RansomwareRule(),
            new DataDestructionRule(),
            // Sysmon rules
            new LsassAccessRule(),
            new RemoteThreadInjectionRule(),
            new DllSideloadRule(),
            new EncodedPowerShellRule(),
            new NamedPipeC2Rule(),
            new OfficeChildProcessRule(),
            new WmiPersistenceRule(),
            new LolBinIngressRule(),
            new DefenderTamperingRule(),
            new SuspiciousScCreateRule(),
        };
        var chains = withCorrelation
            ? PredefinedChains.All().ToArray()
            : Array.Empty<ICorrelationChain>();
        var correlation = new CorrelationEngine(chains, NullLogger<CorrelationEngine>.Instance);
        var source = new LocalFolderSource();
        var audit = TestAuditLog.Create();
        var engine = new LogForensicsEngine(
            parsers, rules, _ => source, correlation, audit,
            NullLogger<LogForensicsEngine>.Instance);

        var settings = new ForensicsSettings
        {
            SourceKind = ForensicsSourceKind.LocalFolder,
            LocalPath = scratch,
            LocalRecursive = false,
            EvidenceRoot = Path.Combine(Path.GetTempPath(), "SecAudit.Tests.Ev", Guid.NewGuid().ToString("N")),
        };
        return await engine.RunAsync(settings, new Progress<ForensicsProgress>(_ => { }), CancellationToken.None);
    }

    // ----------------------------------------------------------------------
    // Security-log family (Event 7045 + 1102)
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_backdoor_service_fires_FOR_SVC_and_FOR_CLEAR()
    {
        var result = await RunSingleFixtureAsync("security-backdoor-svc.xml");

        result.Findings.Should().Contain(
            f => f.Id.StartsWith("FOR-SVC-", StringComparison.Ordinal)
              && f.Severity == Severity.Critical,
            because: "Event 7045 with ImagePath under C:\\Users\\Public must flag "
                + "as suspicious service install");

        result.Findings.Should().Contain(
            f => f.Id.StartsWith("FOR-CLEAR-", StringComparison.Ordinal)
              && f.Severity == Severity.Critical,
            because: "Event 1102 (Security log cleared) is a Critical evidence-tampering signal");
    }

    // ----------------------------------------------------------------------
    // Sysmon phishing chain rules (OFFICE-CHAIN, PSENC, LOLBIN-DL)
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_office_phish_fires_three_sysmon_rules()
    {
        var result = await RunSingleFixtureAsync("sysmon-office-phish.xml");

        result.Findings.Should().Contain(f => f.Id.StartsWith("SYSMON-OFFICE-CHAIN-", StringComparison.Ordinal),
            because: "winword.exe → powershell.exe is the canonical macro-phishing signature");
        result.Findings.Should().Contain(f => f.Id.StartsWith("SYSMON-PSENC-", StringComparison.Ordinal),
            because: "powershell with -EncodedCommand must flag");
        result.Findings.Should().Contain(f => f.Id.StartsWith("SYSMON-LOLBIN-DL-", StringComparison.Ordinal),
            because: "certutil -urlcache -split -f http://… is LOLBAS ingress tool transfer");
    }

    // ----------------------------------------------------------------------
    // Sysmon credential-access rules (LSASS)
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_lsass_dump_fires_SYSMON_LSASS()
    {
        var result = await RunSingleFixtureAsync("sysmon-lsass-dump.xml");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-LSASS-", StringComparison.Ordinal)
            && f.Severity == Severity.Critical,
            because: "ProcessAccess to lsass.exe with mask 0x1410 from non-benign source is Mimikatz-style");
    }

    // ----------------------------------------------------------------------
    // Sysmon injection + side-loading rules
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_inject_sideload_fires_both_rules()
    {
        var result = await RunSingleFixtureAsync("sysmon-inject-sideload.xml");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-INJECT-", StringComparison.Ordinal)
            && f.Severity == Severity.Critical,
            because: "CreateRemoteThread from %TEMP% into lsass.exe is Critical injection");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-SIDELOAD-", StringComparison.Ordinal),
            because: "Microsoft-signed binary loading version.dll from user-writable path "
                + "matches classic DLL side-load pattern (hijacklibs)");
    }

    // ----------------------------------------------------------------------
    // Sysmon C2/WMI persistence rules
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_pipe_wmi_fires_both_rules()
    {
        var result = await RunSingleFixtureAsync("sysmon-pipe-wmi.xml");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-PIPE-", StringComparison.Ordinal)
            && f.Severity == Severity.Critical,
            because: "pipe name \\msagent_3f matches Cobalt Strike default beacon pattern");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-WMI-", StringComparison.Ordinal),
            because: "non-whitelisted WMI event filter/consumer/binding = T1546.003 persistence");

        // Binding is graded Critical by the rule; filter/consumer are High.
        result.Findings.Where(f => f.Id.StartsWith("SYSMON-WMI-", StringComparison.Ordinal))
            .Should().Contain(f => f.Severity == Severity.Critical,
                because: "FilterToConsumerBinding means the persistence is fully wired, not half-built");
    }

    // ----------------------------------------------------------------------
    // Sysmon defense-evasion + service persistence
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_defender_sc_fires_both_rules()
    {
        var result = await RunSingleFixtureAsync("sysmon-defender-sc.xml");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-DEFENDER-OFF-", StringComparison.Ordinal)
            && f.Severity == Severity.Critical,
            because: "Set-MpPreference -DisableRealtimeMonitoring is T1562.001 Impair Defenses");

        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("SYSMON-SC-CREATE-", StringComparison.Ordinal)
            && f.Severity == Severity.Critical,
            because: "sc.exe create with binPath in C:\\Users\\Public\\ + type=own + start=auto is persistence");
    }

    // ----------------------------------------------------------------------
    // Correlation chain — CHAIN-CREDACCESS end-to-end
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Fixture_credaccess_chain_emits_kill_chain_finding()
    {
        // Pivot trong CorrelationEngine = Finding.Asset. LolBinIngressRule và
        // LsassAccessRule đều dùng process:<name> cho source — khi source là
        // powershell.exe, cả 2 stage có pivot = "process:powershell.exe".
        var result = await RunSingleFixtureAsync("sysmon-credaccess-chain.xml", withCorrelation: true);

        // Individual rules fire
        result.Findings.Should().Contain(f => f.Id.StartsWith("SYSMON-LOLBIN-DL-", StringComparison.Ordinal));
        result.Findings.Should().Contain(f => f.Id.StartsWith("SYSMON-LSASS-", StringComparison.Ordinal));

        // Chain fires. Regression guard: CorrelationEngine.PruneStale trước đây
        // dùng record.Timestamp làm "now" còn ChainProgress.Started lại là
        // UtcNow (từ Finding.Create) — khi fixture có date "tương lai" hoặc log
        // historical cách đây hàng tháng, delta > window khiến progress bị
        // prune ngay lập tức. Đã sửa để cả hai dùng cùng UtcNow; chain này
        // xác nhận regression không tái diễn.
        result.Findings.Should().Contain(f =>
            f.Id.StartsWith("CHAIN-CREDACCESS-", StringComparison.Ordinal)
            && f.Category == "log-forensics.kill-chain"
            && f.Severity == Severity.Critical,
            because: "LolBin + LSASS trong cửa sổ 10 phút trên cùng process-pivot là T1003.001");
    }

    // ----------------------------------------------------------------------
    // Parser sanity: every fixture yields > 0 records and the engine produces
    // an integrity manifest entry for each XML file.
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData("security-backdoor-svc.xml")]
    [InlineData("sysmon-office-phish.xml")]
    [InlineData("sysmon-lsass-dump.xml")]
    [InlineData("sysmon-inject-sideload.xml")]
    [InlineData("sysmon-pipe-wmi.xml")]
    [InlineData("sysmon-defender-sc.xml")]
    [InlineData("sysmon-credaccess-chain.xml")]
    public async Task Every_fixture_is_ingested_and_manifested(string fileName)
    {
        var result = await RunSingleFixtureAsync(fileName);
        result.TotalRecords.Should().BeGreaterThan(0,
            because: $"WindowsEventXmlParser must decode at least one <Event> in {fileName}");
        result.Manifest.Should().ContainSingle(
            because: "exactly one XML file is under the scratch folder for this test");
        result.Manifest[0].Sha256.Should().HaveLength(64);
    }
}
