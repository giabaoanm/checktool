using System.Globalization;
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
/// Kiểm thử <c>ForensicsSettings.FromUtc/ToUtc</c> — engine PHẢI bỏ qua record
/// nằm ngoài cửa sổ. Dùng auth.log fixture sinh động với 3 mốc thời gian cách
/// nhau nhiều ngày; BruteForceRule yêu cầu ≥10 fail/user/IP trong 5 phút nên
/// ta tạo 10 attempt trong CÙNG 1 phút cho mỗi mốc.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TimeRangeFilterTests
{
    private static async Task<ForensicsResult> RunAsync(ForensicsSettings settings, IEnumerable<string> authLines)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "SecAudit.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var authPath = Path.Combine(tempDir, "auth.log");
        await File.WriteAllLinesAsync(authPath, authLines);

        settings.LocalPath = tempDir;
        settings.LocalRecursive = false;
        settings.SourceKind = ForensicsSourceKind.LocalFolder;
        settings.EvidenceRoot = Path.Combine(tempDir, "evidence");

        var parsers = new ILogParser[] { new LinuxAuthLogParser() };
        var rules = new IDetectionRule[] { new BruteForceRule() };
        var source = new LocalFolderSource();
        var audit = TestAuditLog.Create();
        var correlation = new CorrelationEngine(
            Array.Empty<ICorrelationChain>(),
            NullLogger<CorrelationEngine>.Instance);
        var engine = new LogForensicsEngine(
            parsers, rules, _ => source, correlation, audit,
            NullLogger<LogForensicsEngine>.Instance);

        return await engine.RunAsync(settings, new Progress<ForensicsProgress>(_ => { }), CancellationToken.None);
    }

    /// <summary>Generate 10 failed-logon lines tại một thời điểm cho user/ip cố định
    /// (BruteForceRule threshold = 10).</summary>
    private const int BurstSize = 10;
    private static IEnumerable<string> BurstAt(DateTime ts, string user = "bob", string ip = "1.2.3.4")
    {
        for (int i = 0; i < BurstSize; i++)
        {
            // Format syslog chuẩn: "Mon DD HH:MM:SS host sshd[pid]: Failed password for user from ip port N ssh2".
            // InvariantCulture để parser (cũng dùng Invariant) khớp được tên tháng ("Apr" không phải "Thg4").
            var t = ts.AddSeconds(i);
            var line = string.Format(
                CultureInfo.InvariantCulture,
                "{0:MMM} {1,2} {2:HH:mm:ss} host01 sshd[{3}]: Failed password for {4} from {5} port 54321 ssh2",
                t, t.Day, t, 1000 + i, user, ip);
            yield return line;
        }
    }

    [Fact]
    public async Task NoWindow_DetectsAllBursts()
    {
        // 3 burst: 10 ngày trước, 5 ngày trước, hôm nay. Không set FromUtc/ToUtc —
        // expect detect tất cả (ít nhất 1 BruteForce finding).
        var now = DateTime.Now;
        var lines = BurstAt(now.AddDays(-10), "alice").Concat(
                    BurstAt(now.AddDays(-5),  "bob")).Concat(
                    BurstAt(now,              "carol"));

        var result = await RunAsync(new ForensicsSettings(), lines);

        result.Findings.Should().Contain(f => f.Id.StartsWith("FOR-BRUTE", StringComparison.Ordinal));
        result.TotalRecords.Should().Be(30);
    }

    [Fact]
    public async Task FromUtcCutoff_SkipsRecordsBefore()
    {
        var now = DateTime.Now;
        var lines = BurstAt(now.AddDays(-10), "alice").Concat(
                    BurstAt(now.AddDays(-5),  "bob")).Concat(
                    BurstAt(now,              "carol"));

        // Cutoff 2 ngày trước → chỉ burst "carol" hôm nay được vào engine.
        var settings = new ForensicsSettings
        {
            FromUtc = DateTimeOffset.Now.AddDays(-2).ToUniversalTime()
        };

        var result = await RunAsync(settings, lines);

        // Chỉ 10 record đi qua time filter.
        result.TotalRecords.Should().Be(10);
        // BruteForceRule vẫn fire vì có 10 fail cùng user/IP trong window nội bộ.
        result.Findings.Should().Contain(f => f.Evidence.Contains("carol", StringComparison.Ordinal));
        result.Findings.Should().NotContain(f => f.Evidence.Contains("alice", StringComparison.Ordinal));
        result.Findings.Should().NotContain(f => f.Evidence.Contains("bob", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ToUtcCutoff_SkipsRecordsAfter()
    {
        var now = DateTime.Now;
        var lines = BurstAt(now.AddDays(-10), "alice").Concat(
                    BurstAt(now.AddDays(-5),  "bob")).Concat(
                    BurstAt(now,              "carol"));

        // Cutoff trên là 7 ngày trước → chỉ alice vào engine.
        var settings = new ForensicsSettings
        {
            ToUtc = DateTimeOffset.Now.AddDays(-7).ToUniversalTime()
        };

        var result = await RunAsync(settings, lines);

        result.TotalRecords.Should().Be(10);
        result.Findings.Should().Contain(f => f.Evidence.Contains("alice", StringComparison.Ordinal));
        result.Findings.Should().NotContain(f => f.Evidence.Contains("bob", StringComparison.Ordinal));
        result.Findings.Should().NotContain(f => f.Evidence.Contains("carol", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BothBounds_OnlyMiddleBurst()
    {
        var now = DateTime.Now;
        var lines = BurstAt(now.AddDays(-10), "alice").Concat(
                    BurstAt(now.AddDays(-5),  "bob")).Concat(
                    BurstAt(now,              "carol"));

        // Window 7..2 ngày trước → chỉ "bob" (-5d).
        var settings = new ForensicsSettings
        {
            FromUtc = DateTimeOffset.Now.AddDays(-7).ToUniversalTime(),
            ToUtc = DateTimeOffset.Now.AddDays(-2).ToUniversalTime()
        };

        var result = await RunAsync(settings, lines);

        result.TotalRecords.Should().Be(10);
        result.Findings.Should().Contain(f => f.Evidence.Contains("bob", StringComparison.Ordinal));
    }
}
