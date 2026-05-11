using SecAudit.Modules.LogForensics.LinuxIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Conditional test that runs end-to-end on the real victim OCI bundle and writes
/// a sample report next to it so the user can preview the actual output without
/// launching the GUI. Auto-skips when the fixture is not present.
/// </summary>
public sealed class LinuxIncidentRealVictimReportSample
{
    private const string VictimBundle = @"C:\Users\Admin\Desktop\LOG VIRUS\victim\victim";
    private const string OutDir = @"C:\Users\Admin\Desktop\LOG VIRUS\victim\AI";

    [Fact]
    public void Generate_sample_report_from_real_victim_image()
    {
        // Diagnostic — write probe info to the OutDir even when we skip, so we can
        // see WHY the test skipped on this dev machine.
        try
        {
            Directory.CreateDirectory(OutDir);
            var probe = $"victim path: {VictimBundle}\n"
                      + $"Directory.Exists: {Directory.Exists(VictimBundle)}\n"
                      + $"LooksLikeOciBundle: {OciImageExtractor.LooksLikeOciBundle(VictimBundle)}\n"
                      + $"oci-layout: {File.Exists(Path.Combine(VictimBundle, "oci-layout"))}\n"
                      + $"index.json: {File.Exists(Path.Combine(VictimBundle, "index.json"))}\n"
                      + $"blobs/sha256/: {Directory.Exists(Path.Combine(VictimBundle, "blobs", "sha256"))}\n";
            File.WriteAllText(Path.Combine(OutDir, "linux-ir-probe.txt"), probe);
        }
        catch { /* best effort */ }

        if (!OciImageExtractor.LooksLikeOciBundle(VictimBundle))
        {
            return; // skip on dev machines without the fixture
        }

        var temp = Path.Combine(Path.GetTempPath(),
            "secaudit-victim-report-" + Guid.NewGuid().ToString("N")[..10]);
        try
        {
            new OciImageExtractor().Extract(VictimBundle, temp, CancellationToken.None);
            var ar = new LinuxIncidentAnalyzer().Analyze(temp, "DAVE", CancellationToken.None);

            var ctx = new LinuxIncidentReportBuilder.ReportContext(
                Asset: "DAVE",
                SourcePath: VictimBundle,
                GeneratedAt: DateTimeOffset.Now,
                Result: ar);

            Directory.CreateDirectory(OutDir);
            var stem = "secaudit-linux-DAVE-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            File.WriteAllText(Path.Combine(OutDir, stem + ".md"),
                LinuxIncidentReportBuilder.BuildMarkdown(ctx));
            File.WriteAllText(Path.Combine(OutDir, stem + ".html"),
                LinuxIncidentReportBuilder.BuildHtml(ctx));
        }
        finally
        {
            try { Directory.Delete(temp, recursive: true); } catch { /* best effort */ }
        }
    }
}
