using System.Text;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;

namespace SecAudit.Modules.LogForensics.Correlation;

/// <summary>
/// Stateful correlation engine. Sau khi mỗi <see cref="LogRecord"/> đi qua các
/// <see cref="IDetectionRule"/>, engine này snapshot mọi Finding mới được Emit
/// ra <see cref="ForensicsContext"/> và gán với pivot key (host — dùng
/// <c>ctx.MachineName</c> là tốt nhất trong v1 vì đa số scan single-host).
///
/// Mỗi chain là một state machine tiến tới stage tiếp theo mỗi khi gặp rule
/// trùng prefix. Khi đủ stage trong cửa sổ thời gian → engine emit một
/// Finding "kill-chain" mới với severity Critical.
///
/// Thread-safety: được gọi tuần tự từ <c>LogForensicsEngine.RunAsync</c> —
/// không cần lock.
/// </summary>
public sealed class CorrelationEngine
{
    private readonly IReadOnlyList<ICorrelationChain> _chains;
    private readonly ILogger<CorrelationEngine> _log;

    /// <summary>Số Finding đã observe lần cuối — để tách diff mỗi lần record mới.</summary>
    private int _lastObservedFindingCount;

    /// <summary>
    /// State machines đang chạy, key = chainId + "|" + pivotKey.
    /// Một host có thể trigger cùng một chain nhiều lần, nhưng ta chỉ giữ
    /// 1 progress tại một thời điểm — emit xong reset.
    /// </summary>
    private readonly Dictionary<string, ChainProgress> _active = new(StringComparer.Ordinal);

    /// <summary>Dedup các kill-chain finding đã emit (tránh phát 2 lần cho cùng intrusion).</summary>
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public CorrelationEngine(IEnumerable<ICorrelationChain> chains, ILogger<CorrelationEngine> log)
    {
        _chains = chains.ToList();
        _log = log;
    }

    public void Reset()
    {
        _lastObservedFindingCount = 0;
        _active.Clear();
        _emitted.Clear();
    }

    /// <summary>
    /// Gọi sau mỗi record. Engine diff Findings trong ctx vs lần trước để biết
    /// rule nào vừa emit, rồi feed vào state machines.
    /// </summary>
    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        var findings = ctx.Findings;
        if (findings.Count <= _lastObservedFindingCount) { return; }

        for (int i = _lastObservedFindingCount; i < findings.Count; i++)
        {
            var f = findings[i];
            // Bỏ qua chính kill-chain finding — tránh recursion.
            if (f.Category.StartsWith("log-forensics.kill-chain", StringComparison.Ordinal)) { continue; }

            AdvanceChains(f, ctx);
        }
        _lastObservedFindingCount = findings.Count;

        PruneStale(record.Timestamp);
    }

    /// <summary>
    /// Cuối run — catch các finding từ rule.Flush() mà chưa được diff.
    /// </summary>
    public void Flush(ForensicsContext ctx)
    {
        var findings = ctx.Findings;
        for (int i = _lastObservedFindingCount; i < findings.Count; i++)
        {
            var f = findings[i];
            if (f.Category.StartsWith("log-forensics.kill-chain", StringComparison.Ordinal)) { continue; }
            AdvanceChains(f, ctx);
        }
        _lastObservedFindingCount = findings.Count;
    }

    private void AdvanceChains(Finding f, ForensicsContext ctx)
    {
        foreach (var chain in _chains)
        {
            // Stage hiện tại là stage[progress.NextStageIndex]. Nếu chưa có
            // progress cho chain này thì chỉ nhận stage 0.
            var pivot = ExtractPivot(f, ctx);
            var key = chain.Id + "|" + pivot;

            if (!_active.TryGetValue(key, out var progress))
            {
                if (StageMatches(chain.Stages[0], f))
                {
                    _active[key] = new ChainProgress(chain, pivot, f);
                }
                continue;
            }

            var expected = chain.Stages[progress.NextStageIndex];
            if (!StageMatches(expected, f))
            {
                continue;
            }

            // Enforce cửa sổ tính từ finding đầu.
            if (f.DetectedAt - progress.Started > chain.Window)
            {
                // Cửa sổ hết — restart nếu finding này cũng khớp stage 0.
                _active.Remove(key);
                if (StageMatches(chain.Stages[0], f))
                {
                    _active[key] = new ChainProgress(chain, pivot, f);
                }
                continue;
            }

            progress.Add(f);

            if (progress.IsComplete)
            {
                EmitChainFinding(chain, progress, ctx);
                _active.Remove(key);
            }
        }
    }

    private static bool StageMatches(ChainStage stage, Finding f)
    {
        foreach (var prefix in stage.AcceptedRuleIdPrefixes)
        {
            if (f.Id.StartsWith(prefix, StringComparison.Ordinal)) { return true; }
        }
        return false;
    }

    /// <summary>
    /// Pivot key — dùng phần "asset" của finding (process:xxx / host:xxx /
    /// user:xxx) khi có, fallback về machine name. Trong tương lai có thể
    /// parse asset ra host/user/process riêng.
    /// </summary>
    private static string ExtractPivot(Finding f, ForensicsContext ctx)
    {
        if (!string.IsNullOrWhiteSpace(f.Asset))
        {
            // Bóc prefix "host:" / "process:" vì đối với correlation chúng ta
            // muốn cùng một host là 1 nhóm. Giữ nguyên nguyên chuỗi để phân
            // biệt giữa process:winword.exe và process:powershell.exe.
            return f.Asset;
        }
        return "host:" + ctx.MachineName;
    }

    private void PruneStale(DateTimeOffset now)
    {
        if (_active.Count == 0) { return; }
        List<string>? toRemove = null;
        foreach (var kv in _active)
        {
            if (now - kv.Value.Started > kv.Value.Chain.Window)
            {
                toRemove ??= new List<string>();
                toRemove.Add(kv.Key);
            }
        }
        if (toRemove is not null)
        {
            foreach (var k in toRemove) { _active.Remove(k); }
        }
    }

    private void EmitChainFinding(ICorrelationChain chain, ChainProgress progress, ForensicsContext ctx)
    {
        var dedupKey = chain.Id + "|" + progress.Pivot + "|" + progress.Started.ToString("u");
        if (!_emitted.Add(dedupKey))
        {
            _log.LogDebug("Skipping duplicate kill-chain {Chain} on {Pivot}", chain.Id, progress.Pivot);
            return;
        }

        var sb = new StringBuilder();
        sb.Append("Kill chain: ").Append(chain.KillChain).AppendLine();
        sb.Append("Pivot: ").Append(progress.Pivot).AppendLine();
        sb.Append("Duration: ").Append((progress.Last.DetectedAt - progress.Started).TotalSeconds.ToString("F1"))
          .AppendLine(" giây").AppendLine();
        for (int i = 0; i < progress.Matched.Count; i++)
        {
            var step = progress.Matched[i];
            sb.Append('[').Append(i + 1).Append("] ")
              .Append(chain.Stages[i].Label).Append(" — ")
              .Append(step.DetectedAt.ToString("u")).AppendLine()
              .Append("    ").Append(step.Title).AppendLine()
              .Append("    id=").Append(step.Id).AppendLine();
        }

        var finding = Finding.Create(
            id: $"{chain.Id}-{SysmonHashStableFnv(dedupKey)}",
            title: $"[KILL-CHAIN] {chain.Name}",
            severity: chain.FinalSeverity,
            category: "log-forensics.kill-chain",
            asset: progress.Pivot,
            evidence: sb.ToString(),
            remediation:
                "Chain tấn công đã match — xử lý khẩn: (1) cô lập host khỏi mạng; "
                + "(2) thu thập memory dump + disk image trước khi reboot; "
                + "(3) tra các Finding con (xem list trong Evidence) để lấy IOC cụ thể; "
                + "(4) rà soát lateral movement sang host khác; "
                + "(5) cân nhắc reimage thay vì chỉ khôi phục.",
            references: chain.References);

        ctx.Emit(finding);
        _log.LogWarning("Correlation emitted kill-chain {Chain} on {Pivot}", chain.Id, progress.Pivot);
    }

    /// <summary>FNV-1a 32-bit — stable hash for finding IDs (same as SysmonHelpers).</summary>
    private static string SysmonHashStableFnv(string input)
    {
        unchecked
        {
            const uint offset = 2166136261u;
            const uint prime = 16777619u;
            uint h = offset;
            foreach (var c in input) { h ^= c; h *= prime; }
            return h.ToString("X8");
        }
    }

    /// <summary>Trạng thái chạy của một chain — track stage kế tiếp + các finding đã matched.</summary>
    private sealed class ChainProgress
    {
        public ICorrelationChain Chain { get; }
        public string Pivot { get; }
        public DateTimeOffset Started { get; }
        public List<Finding> Matched { get; } = new();
        public int NextStageIndex => Matched.Count;
        public bool IsComplete => Matched.Count >= Chain.Stages.Count;
        public Finding Last => Matched[^1];

        public ChainProgress(ICorrelationChain chain, string pivot, Finding first)
        {
            Chain = chain;
            Pivot = pivot;
            Started = first.DetectedAt;
            Matched.Add(first);
        }

        public void Add(Finding f) => Matched.Add(f);
    }
}
