namespace SecAudit.Plugins.Abstractions;

/// <summary>
/// Result returned by a module run. Findings are typed as object to keep this assembly free of
/// dependencies on SecAudit.Core (Finding lives there). The shell aggregator casts back.
/// </summary>
public sealed class ModuleResult
{
    public required string ModuleId { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required bool Succeeded { get; init; }
    public string? FailureReason { get; init; }
    public required IReadOnlyList<object> Findings { get; init; }

    public TimeSpan Duration => CompletedAt - StartedAt;
}
