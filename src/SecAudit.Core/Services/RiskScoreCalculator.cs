using SecAudit.Core.Models;

namespace SecAudit.Core.Services;

/// <summary>
/// Computes a 0-100 risk score from a set of findings. Each severity contributes a fixed
/// penalty; the score is 100 minus the sum, clamped to [0,100]. Tunable weights allow per-module
/// overrides via configuration.
/// </summary>
public sealed class RiskScoreCalculator
{
    private readonly IReadOnlyDictionary<Severity, int> _weights;

    public RiskScoreCalculator() : this(DefaultWeights) { }

    public RiskScoreCalculator(IReadOnlyDictionary<Severity, int> weights)
    {
        _weights = weights;
    }

    public static IReadOnlyDictionary<Severity, int> DefaultWeights { get; } =
        new Dictionary<Severity, int>
        {
            [Severity.Info] = 0,
            [Severity.Low] = 2,
            [Severity.Medium] = 5,
            [Severity.High] = 12,
            [Severity.Critical] = 25
        };

    public RiskScore Score(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var penalty = 0;
        foreach (var f in findings)
        {
            if (_weights.TryGetValue(f.Severity, out var w))
            {
                penalty += w;
            }
        }
        return RiskScore.FromValue(100 - penalty);
    }
}
