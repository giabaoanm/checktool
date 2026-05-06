using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class ServerAttackAnalyzerTests
{
    [Fact]
    public void BuildFindings_flags_bruteforce_and_success_after_failures()
    {
        var analyzer = new ServerAttackAnalyzer();
        var baseTime = DateTimeOffset.UtcNow.AddMinutes(-30);

        for (int i = 0; i < 12; i++)
        {
            analyzer.Observe(Record(
                "logon.failed",
                baseTime.AddSeconds(i),
                new Dictionary<string, string>
                {
                    ["IpAddress"] = "203.0.113.10",
                    ["TargetUserName"] = "administrator"
                }), "srv01");
        }

        analyzer.Observe(Record(
            "logon.success",
            baseTime.AddMinutes(1),
            new Dictionary<string, string>
            {
                ["IpAddress"] = "203.0.113.10",
                ["TargetUserName"] = "administrator"
            }), "srv01");

        var findings = analyzer.BuildFindings("srv01");

        findings.Should().Contain(f => f.Category == "server-attack.brute-force");
        findings.Should().Contain(f => f.Category == "server-attack.compromise-suspected"
                                      && f.Severity == Severity.Critical);
    }

    [Fact]
    public void BuildFindings_flags_web_scanner_and_exploit_probes()
    {
        var analyzer = new ServerAttackAnalyzer();
        var baseTime = DateTimeOffset.UtcNow.AddMinutes(-10);

        analyzer.Observe(Record(
            "http.request",
            baseTime,
            new Dictionary<string, string>
            {
                ["IpAddress"] = "198.51.100.20",
                ["Uri"] = "/index.aspx?id=1",
                ["UserAgent"] = "sqlmap/1.8"
            }), "srv01");

        foreach (var uri in new[] { "/.env", "/wp-login.php", "/phpmyadmin/", "/cgi-bin/test", "/?cmd=powershell" })
        {
            analyzer.Observe(Record(
                "http.request",
                baseTime.AddSeconds(1),
                new Dictionary<string, string>
                {
                    ["IpAddress"] = "198.51.100.20",
                    ["Uri"] = uri,
                    ["UserAgent"] = "Mozilla/5.0"
                }), "srv01");
        }

        var findings = analyzer.BuildFindings("srv01");

        findings.Should().Contain(f => f.Category == "server-attack.web-scan"
                                      && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Observe_flags_web_server_spawning_shell()
    {
        var analyzer = new ServerAttackAnalyzer();

        analyzer.Observe(Record(
            "process.created",
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>
            {
                ["ParentProcessName"] = @"C:\Windows\System32\inetsrv\w3wp.exe",
                ["NewProcessName"] = @"C:\Windows\System32\cmd.exe",
                ["CommandLine"] = "cmd.exe /c whoami"
            }), "srv01");

        var findings = analyzer.BuildFindings("srv01");

        findings.Should().Contain(f => f.Category == "server-attack.webshell"
                                      && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Observe_flags_lsass_process_access()
    {
        var analyzer = new ServerAttackAnalyzer();

        analyzer.Observe(Record(
            "sysmon.processaccess",
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>
            {
                ["SourceImage"] = @"C:\Temp\dump.exe",
                ["TargetImage"] = @"C:\Windows\System32\lsass.exe",
                ["GrantedAccess"] = "0x1010"
            }), "srv01");

        var findings = analyzer.BuildFindings("srv01");

        findings.Should().Contain(f => f.Category == "server-attack.credential-access"
                                      && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Observe_suppresses_known_asus_iomap_service_install_noise()
    {
        var analyzer = new ServerAttackAnalyzer();

        analyzer.Observe(Record(
            "service.installed",
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>
            {
                ["ServiceName"] = "IOMap",
                ["ImagePath"] = @"\??\C:\Windows\system32\drivers\IOMap64.sys",
                ["ServiceType"] = "kernel mode driver",
                ["StartType"] = "demand start"
            }), "srv01");

        var findings = analyzer.BuildFindings("srv01");

        findings.Should().NotContain(f => f.Category == "server-attack.persistence.service");
    }

    [Fact]
    public void Observe_deduplicates_service_installs_by_service_and_path()
    {
        var analyzer = new ServerAttackAnalyzer();

        for (int i = 0; i < 2; i++)
        {
            analyzer.Observe(Record(
                "service.installed",
                DateTimeOffset.UtcNow.AddSeconds(i),
                new Dictionary<string, string>
                {
                    ["ServiceName"] = "SuspSvc",
                    ["ImagePath"] = @"C:\ProgramData\Vendor\service.exe",
                    ["StartType"] = "demand start"
                }), "srv01");
        }

        var findings = analyzer.BuildFindings("srv01");

        findings.Where(f => f.Category == "server-attack.persistence.service")
            .Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public void Observe_keeps_temp_service_install_high()
    {
        var analyzer = new ServerAttackAnalyzer();

        analyzer.Observe(Record(
            "service.installed",
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>
            {
                ["ServiceName"] = "TempSvc",
                ["ImagePath"] = @"C:\Users\Admin\AppData\Local\Temp\svc.exe",
                ["StartType"] = "demand start"
            }), "srv01");

        var findings = analyzer.BuildFindings("srv01");

        findings.Should().Contain(f => f.Category == "server-attack.persistence.service"
                                      && f.Severity == Severity.High);
    }

    private static LogRecord Record(
        string kind,
        DateTimeOffset timestamp,
        IReadOnlyDictionary<string, string> fields) =>
        new()
        {
            Timestamp = timestamp,
            SourceFile = "unit-test",
            SourceOffset = 1,
            Os = "windows",
            RawLine = kind,
            EventKind = kind,
            Fields = fields
        };
}
