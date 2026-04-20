using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Correlation;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Kiểm thử <see cref="CorrelationEngine"/> độc lập với parser/rule — ta feed
/// trực tiếp các Finding giả lập vào ForensicsContext rồi gọi Observe để xác
/// minh state machine hoạt động đúng.
/// </summary>
public sealed class CorrelationEngineTests
{
    private static readonly string[] FakeRefs = { "MITRE ATT&CK T9999" };

    private static ForensicsContext Ctx() => new()
    {
        UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        InternalCidrs = Array.Empty<CidrRange>(),
        MachineName = "TEST-HOST"
    };

    private static LogRecord Rec(DateTimeOffset ts) => new()
    {
        Timestamp = ts,
        SourceFile = "fake",
        SourceOffset = 1,
        Os = "windows",
        RawLine = string.Empty,
        EventKind = "sysmon.process"
    };

    private static Finding Find(string id, DateTimeOffset ts, string asset = "host:TEST-HOST") => new(
        Id: id,
        Title: id,
        Severity: Severity.High,
        CvssScore: null,
        Category: "log-forensics.test",
        Asset: asset,
        Evidence: "e",
        Remediation: "r",
        References: Array.Empty<string>(),
        DetectedAt: ts);

    private static readonly string[] StageA = { "RULE-A" };
    private static readonly string[] StageB = { "RULE-B" };
    private static readonly string[] StageC = { "RULE-C" };

    private static TestChain MakeChain(TimeSpan window, params string[][] stages)
    {
        return new TestChain(
            id: "CHAIN-TEST",
            window: window,
            stages: stages.Select((s, i) => new ChainStage("S" + i, s)).ToArray());
    }

    private sealed class TestChain : ICorrelationChain
    {
        public string Id { get; }
        public string Name => "Test chain";
        public string KillChain => "Test";
        public IReadOnlyList<ChainStage> Stages { get; }
        public TimeSpan Window { get; }
        public Severity FinalSeverity => Severity.Critical;
        public IReadOnlyList<string> References => FakeRefs;
        public TestChain(string id, TimeSpan window, IReadOnlyList<ChainStage> stages)
        { Id = id; Window = window; Stages = stages; }
    }

    [Fact]
    public void EmitsKillChain_WhenAllStagesMatchInOrderWithinWindow()
    {
        var chain = MakeChain(TimeSpan.FromMinutes(5), StageA, StageB, StageC);
        var eng = new CorrelationEngine(new[] { chain }, NullLogger<CorrelationEngine>.Instance);
        var ctx = Ctx();
        var t0 = DateTimeOffset.UtcNow;

        ctx.Emit(Find("RULE-A-x1", t0));
        eng.Observe(Rec(t0), ctx);
        ctx.Emit(Find("RULE-B-x2", t0.AddSeconds(10)));
        eng.Observe(Rec(t0.AddSeconds(10)), ctx);
        ctx.Emit(Find("RULE-C-x3", t0.AddSeconds(20)));
        eng.Observe(Rec(t0.AddSeconds(20)), ctx);

        ctx.Findings.Should().Contain(f => f.Id.StartsWith("CHAIN-TEST-", StringComparison.Ordinal));
        var chainFinding = ctx.Findings.First(f => f.Category == "log-forensics.kill-chain");
        chainFinding.Severity.Should().Be(Severity.Critical);
        chainFinding.Evidence.Should().Contain("RULE-A-x1")
            .And.Contain("RULE-B-x2")
            .And.Contain("RULE-C-x3");
    }

    [Fact]
    public void DoesNotEmit_WhenStagesOutsideWindow()
    {
        var chain = MakeChain(TimeSpan.FromMinutes(1), StageA, StageB);
        var eng = new CorrelationEngine(new[] { chain }, NullLogger<CorrelationEngine>.Instance);
        var ctx = Ctx();
        var t0 = DateTimeOffset.UtcNow;

        ctx.Emit(Find("RULE-A-1", t0));
        eng.Observe(Rec(t0), ctx);
        // Stage B đến muộn sau 5 phút — quá window 1 phút.
        ctx.Emit(Find("RULE-B-1", t0.AddMinutes(5)));
        eng.Observe(Rec(t0.AddMinutes(5)), ctx);

        ctx.Findings.Should().NotContain(f => f.Category == "log-forensics.kill-chain");
    }

    [Fact]
    public void DoesNotEmit_WhenStagesWrongOrder()
    {
        var chain = MakeChain(TimeSpan.FromMinutes(5), StageA, StageB);
        var eng = new CorrelationEngine(new[] { chain }, NullLogger<CorrelationEngine>.Instance);
        var ctx = Ctx();
        var t0 = DateTimeOffset.UtcNow;

        // Stage B đến trước stage A → engine bỏ qua stage B (chưa có progress)
        // rồi khởi tạo progress khi thấy stage A, nhưng sau đó không có B mới.
        ctx.Emit(Find("RULE-B-1", t0));
        eng.Observe(Rec(t0), ctx);
        ctx.Emit(Find("RULE-A-1", t0.AddSeconds(10)));
        eng.Observe(Rec(t0.AddSeconds(10)), ctx);

        ctx.Findings.Should().NotContain(f => f.Category == "log-forensics.kill-chain");
    }

    [Fact]
    public void Reset_ClearsStateBetweenRuns()
    {
        var chain = MakeChain(TimeSpan.FromMinutes(5), StageA, StageB);
        var eng = new CorrelationEngine(new[] { chain }, NullLogger<CorrelationEngine>.Instance);
        var ctx1 = Ctx();
        var t0 = DateTimeOffset.UtcNow;

        // Run 1 — chỉ match stage A.
        ctx1.Emit(Find("RULE-A-1", t0));
        eng.Observe(Rec(t0), ctx1);

        eng.Reset();

        // Run 2 — chỉ emit stage B. Nếu Reset không dọn _active, stage A dư
        // từ run 1 sẽ khiến engine phát kill-chain oan.
        var ctx2 = Ctx();
        ctx2.Emit(Find("RULE-B-1", t0.AddMinutes(1)));
        eng.Observe(Rec(t0.AddMinutes(1)), ctx2);

        ctx2.Findings.Should().NotContain(f => f.Category == "log-forensics.kill-chain");
    }

    [Fact]
    public void IgnoresSelfEmittedChainFindings_NoRecursion()
    {
        // Chain A → B; nếu engine không filter chính các kill-chain finding mà
        // cho chúng feed lại state machine, bug vô hạn. Test: feed 1 chain
        // finding giả có prefix "log-forensics.kill-chain" và expect engine bỏ qua.
        var chain = MakeChain(TimeSpan.FromMinutes(5), StageA, StageB);
        var eng = new CorrelationEngine(new[] { chain }, NullLogger<CorrelationEngine>.Instance);
        var ctx = Ctx();
        var t0 = DateTimeOffset.UtcNow;

        ctx.Emit(new Finding(
            Id: "CHAIN-FAKE-1",
            Title: "fake chain",
            Severity: Severity.Critical,
            CvssScore: null,
            Category: "log-forensics.kill-chain",
            Asset: "host:TEST-HOST",
            Evidence: "e",
            Remediation: "r",
            References: Array.Empty<string>(),
            DetectedAt: t0));
        eng.Observe(Rec(t0), ctx);

        // Feed một Stage-B hợp lệ — sẽ KHÔNG match vì chưa có stage A progress
        // (kill-chain input đã bị filter).
        ctx.Emit(Find("RULE-B-1", t0.AddSeconds(1)));
        eng.Observe(Rec(t0.AddSeconds(1)), ctx);

        ctx.Findings.Count(f => f.Id.StartsWith("CHAIN-TEST-", StringComparison.Ordinal)).Should().Be(0);
    }

    [Fact]
    public void AllPredefinedChainsHaveUniqueIdsAndMinTwoStages()
    {
        var all = PredefinedChains.All().ToList();
        all.Should().HaveCountGreaterOrEqualTo(8);
        all.Select(c => c.Id).Should().OnlyHaveUniqueItems();
        all.Should().OnlyContain(c => c.Stages.Count >= 2);
        all.Should().OnlyContain(c => c.Window > TimeSpan.Zero);
        all.Should().OnlyContain(c => c.References.Count > 0);
    }
}
