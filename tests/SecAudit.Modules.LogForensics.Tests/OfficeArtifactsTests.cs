using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Office;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class OfficeArtifactsTests : IDisposable
{
    private readonly string _tmp;

    public OfficeArtifactsTests()
    {
        _tmp = Path.Combine(Path.GetTempPath(),
            "secaudit-ofc-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_tmp);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void Analyzer_flags_macro_file_in_user_Downloads()
    {
        var users = Path.Combine(_tmp, "Users");
        var dl = Path.Combine(users, "alice", "Downloads");
        Directory.CreateDirectory(dl);
        File.WriteAllText(Path.Combine(dl, "Cong-van.docm"), "fake");
        File.WriteAllText(Path.Combine(dl, "report.xlsm"), "fake");

        var ar = new OfficeArtifactsAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.MacroFilesScanned.Should().Be(2);
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("OFC-MACRO-FILE-")
            && f.Severity == Severity.Medium
            && f.Title.Contains("alice", StringComparison.Ordinal)
            && f.Title.Contains(".docm", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyzer_flags_executable_in_outlook_cache()
    {
        var users = Path.Combine(_tmp, "Users");
        var cache = Path.Combine(users, "bob",
            "AppData", "Local", "Microsoft", "Windows", "INetCache", "Content.Outlook", "ABC123");
        Directory.CreateDirectory(cache);
        File.WriteAllText(Path.Combine(cache, "invoice.exe"), "MZ");
        File.WriteAllText(Path.Combine(cache, "quote.docm"), "macro");
        File.WriteAllText(Path.Combine(cache, "ignore.txt"), "plain"); // not flagged

        var ar = new OfficeArtifactsAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.OutlookCacheFilesScanned.Should().Be(2); // exe + docm, txt skipped
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("OFC-OUTLOOK-CACHE-")
            && f.Severity == Severity.High
            && f.Evidence.Contains("invoice.exe", StringComparison.Ordinal));
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("OFC-OUTLOOK-CACHE-")
            && f.Severity == Severity.Medium
            && f.Evidence.Contains("quote.docm", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyzer_skips_default_user_directories()
    {
        var users = Path.Combine(_tmp, "Users");
        foreach (var skipName in new[] { "Public", "Default", "All Users" })
        {
            var dl = Path.Combine(users, skipName, "Downloads");
            Directory.CreateDirectory(dl);
            File.WriteAllText(Path.Combine(dl, "should-not-flag.docm"), "x");
        }

        var ar = new OfficeArtifactsAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.Findings.Where(f => f.Id.StartsWith("OFC-MACRO-FILE-"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Analyzer_returns_empty_for_no_users_dir()
    {
        var users = Path.Combine(_tmp, "no-such-folder");
        var ar = new OfficeArtifactsAnalyzer().Analyze(users, "TEST", CancellationToken.None);
        ar.MacroFilesScanned.Should().Be(0);
        ar.OutlookCacheFilesScanned.Should().Be(0);
    }

    [Fact]
    public void Analyzer_finds_macro_in_temp_with_medium_severity()
    {
        var users = Path.Combine(_tmp, "Users");
        var temp = Path.Combine(users, "carol", "AppData", "Local", "Temp");
        Directory.CreateDirectory(temp);
        File.WriteAllText(Path.Combine(temp, "stage.dotm"), "x");

        var ar = new OfficeArtifactsAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("OFC-MACRO-FILE-")
            && f.Severity == Severity.Medium
            && f.Evidence.Contains("Temp", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyzer_finds_macro_in_documents_with_low_severity()
    {
        var users = Path.Combine(_tmp, "Users");
        var docs = Path.Combine(users, "dave", "Documents");
        Directory.CreateDirectory(docs);
        File.WriteAllText(Path.Combine(docs, "MyTemplate.dotm"), "x");

        var ar = new OfficeArtifactsAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("OFC-MACRO-FILE-")
            && f.Severity == Severity.Low);
    }
}
