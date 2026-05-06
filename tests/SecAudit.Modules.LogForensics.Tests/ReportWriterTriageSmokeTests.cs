using System.Text.Json;
using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Writers;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class ReportWriterTriageSmokeTests
{
    [Fact]
    public async Task Json_report_includes_operator_triage()
    {
        var finding = Finding.Create(
            "SRV-WEBSHELL",
            "Web worker spawned cmd.exe",
            Severity.Critical,
            "server-attack.webshell",
            "srv01",
            "ParentProcessName=w3wp.exe; NewProcessName=cmd.exe",
            "Isolate server and collect web root evidence.");

        var data = new ReportData(
            AssetName: "srv01",
            GeneratedAt: DateTimeOffset.Parse("2026-05-05T12:00:00+07:00", null),
            Score: RiskScore.FromValue(35),
            ByModule: new Dictionary<string, IReadOnlyList<Finding>>
            {
                ["log-forensics"] = new[] { finding }
            },
            SeverityCounts: new Dictionary<Severity, int>
            {
                [Severity.Critical] = 1
            },
            Device: new DeviceProfile(
                ComputerName: "srv01",
                Cpu: "unit-test",
                CpuCores: 1,
                CpuLogicalProcessors: 1,
                BiosSerial: "unit-test",
                BiosVendor: "unit-test",
                BiosVersion: null,
                BiosReleaseDate: null,
                TotalRam: "1 GB",
                OperatingSystem: "Windows",
                Disks: Array.Empty<DiskSummary>(),
                NetworkAddresses: Array.Empty<NetworkAddress>(),
                TpmPresent: false,
                TpmSpecVersion: null,
                SecureBootEnabled: false),
            License: null,
            Patch: null,
            Scope: null,
            AppliedActions: Array.Empty<AppliedAction>(),
            Recommendations: Array.Empty<Recommendation>(),
            Metadata: new ReportSettings());

        var dir = Path.Combine(Path.GetTempPath(), "SecAudit.ReportWriterTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var jsonPath = Path.Combine(dir, "triage.json");

        await new JsonReportWriter().WriteAsync(data, jsonPath, CancellationToken.None);

        var json = await File.ReadAllTextAsync(jsonPath);

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        root.GetProperty("schemaVersion").GetInt32().Should().Be(8);
        root.GetProperty("operatorTriage").GetProperty("actionGroups")[0].GetProperty("name").GetString()
            .Should().Be("Cần xử lý ngay");
        var triage = root.GetProperty("modules")[0].GetProperty("findings")[0].GetProperty("triage");
        triage.GetProperty("confidence").GetString().Should().Be("Cao");
        triage.GetProperty("actionGroup").GetString().Should().Be("Cần xử lý ngay");
        triage.GetProperty("scenario").GetString().Should().Be("Tấn công trực tuyến");
    }

    [Fact]
    public async Task Html_template_omits_legacy_final_recommendations_section()
    {
        var templatePath = FindRepoFile("src", "SecAudit.Reporting", "Templates", "report.html.sbn");
        var template = await File.ReadAllTextAsync(templatePath);

        template.Should().Contain("f.triage.explanation");
        template.Should().Contain("f.triage.steps");
        template.Should().NotContain("recommendations.size");
        template.Should().NotContain("r.guidance");
    }

    private static string FindRepoFile(params string[] segments)
    {
        var relative = Path.Combine(segments);
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, relative);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("Could not locate repository file.", relative);
    }
}
