using FluentAssertions;
using SecAudit.Modules.LogForensics.WebIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class WebServerEvidenceAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_builds_timeline_webshell_and_baseline_findings()
    {
        var root = Path.Combine(Path.GetTempPath(), "SecAudit.WebIncidentTests", Guid.NewGuid().ToString("N"));
        var evidence = Path.Combine(root, "evidence");
        var server = Path.Combine(root, "server");
        var webroot = Path.Combine(root, "webroot");
        Directory.CreateDirectory(evidence);
        Directory.CreateDirectory(server);
        Directory.CreateDirectory(Path.Combine(webroot, "uploads"));

        await File.WriteAllTextAsync(
            Path.Combine(server, "access.log"),
            """
            203.0.113.10 - - [06/May/2026:10:00:00 +0700] "GET /index.php?id=1%20union%20select%20password HTTP/1.1" 200 123 "-" "sqlmap/1.7"
            203.0.113.10 - - [06/May/2026:10:01:00 +0700] "GET /uploads/avatar.jpg.php?id=1 HTTP/1.1" 200 45 "-" "Mozilla/5.0"
            """);
        await File.WriteAllTextAsync(Path.Combine(webroot, "index.php"), "<?php echo 'changed';");
        await File.WriteAllTextAsync(
            Path.Combine(webroot, "uploads", "avatar.jpg.php"),
            "<?php echo 'benign upload placeholder for SecAudit tests';");
        var baseline = Path.Combine(root, "baseline.csv");
        await File.WriteAllTextAsync(
            baseline,
            """
            RelativePath,SizeBytes,LastWriteUtc,Sha256,Classification
            "index.php","1","2026-05-01T00:00:00.0000000Z","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","webroot"
            """);

        var settings = new WebIncidentSettings
        {
            ServerEvidencePath = server,
            WebRootPath = webroot,
            BaselineManifestPath = baseline
        };

        var result = await new WebServerEvidenceAnalyzer().AnalyzeAsync(
            settings,
            evidence,
            "example.gov.vn",
            CancellationToken.None);

        result.Summary.Should().NotBeNull();
        result.Summary!.Timeline.Should().Contain(e => e.Rule == "SQL injection");
        result.Summary.Timeline.Should().Contain(e => e.Rule == "Possible webshell access");
        result.Summary.SuspiciousFiles.Should().Contain(f => f.RelativePath == "uploads/avatar.jpg.php");
        result.Findings.Select(f => f.Id).Should().Contain(new[]
        {
            "WEB-LOG-SQLI",
            "WEBROOT-WEBSHELL-SUSPECT",
            "WEBROOT-BASELINE-DRIFT"
        });
        result.Manifest.Select(m => m.Name).Should().Contain(new[]
        {
            "web-attack-timeline.csv",
            "webroot-manifest.csv",
            "server-evidence-summary.json"
        });
    }
}
