using FluentAssertions;
using SecAudit.Modules.LogForensics.LinuxIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Conditional smoke test against a real OCI victim image. Auto-skips when the
/// fixture path is not present on the dev machine, so it does not break CI for
/// other contributors but proves end-to-end correctness on the SOC analyst's
/// laptop where the artefact was first observed.
/// </summary>
public sealed class LinuxIncidentRealVictimSmokeTest
{
    private const string VictimBundle = @"C:\Users\Admin\Desktop\LOG VIRUS\victim\victim";

    [Fact]
    public void End_to_end_extracts_OCI_and_emits_CryptoPhantom_findings()
    {
        if (!OciImageExtractor.LooksLikeOciBundle(VictimBundle))
        {
            // Auto-skip when fixture not present — keep the CI green.
            return;
        }

        var temp = Path.Combine(Path.GetTempPath(),
            "secaudit-victim-smoke-" + Guid.NewGuid().ToString("N")[..10]);
        try
        {
            new OciImageExtractor().Extract(VictimBundle, temp, CancellationToken.None);
            var ar = new LinuxIncidentAnalyzer().Analyze(temp, "DAVE", CancellationToken.None);

            // Must catch the ransom note + .locked extension that we know are present.
            ar.Findings.Should().Contain(f => f.Id.StartsWith("LIN-RANSOM-NOTE-"),
                "the README_LOCKED.txt is in the victim image");
            ar.Findings.Should().Contain(f => f.Id == "LIN-ENCRYPTED-EXT-locked",
                "Cong_van_bi_mat.pdf.locked is in the victim image");

            // Must extract the BTC + email IOCs.
            ar.ExtractedIocs.Should().Contain(i => i.Contains("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"));
            ar.ExtractedIocs.Should().Contain(i => i.Contains("phantom_support@protonmail.com"));
        }
        finally
        {
            try { Directory.Delete(temp, recursive: true); } catch { /* best effort */ }
        }
    }
}
