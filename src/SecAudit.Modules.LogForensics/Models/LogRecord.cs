namespace SecAudit.Modules.LogForensics.Models;

/// <summary>
/// Common normalized log record produced by every parser regardless of source format
/// (Windows EVTX, Linux auth.log, nginx access log, bash history, etc.).
///
/// Rules operate on <see cref="LogRecord"/>s without knowing which parser produced them,
/// which is the whole point of normalization — a "failed logon" from Linux or Windows
/// is detectable by the same BruteForceRule.
/// </summary>
public sealed record LogRecord
{
    /// <summary>Time the event occurred (from the log itself, not the scan time).</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Origin file (absolute path or SFTP URI) for chain-of-custody.</summary>
    public required string SourceFile { get; init; }

    /// <summary>1-based line number or EVTX record id for pin-point evidence.</summary>
    public required long SourceOffset { get; init; }

    /// <summary>Normalized OS: "windows" or "linux".</summary>
    public required string Os { get; init; }

    /// <summary>Original raw line (kept verbatim for evidence bundles).</summary>
    public required string RawLine { get; init; }

    /// <summary>
    /// Canonical event kind — stable identifiers rules match on.
    /// Examples: "logon.failed", "logon.success", "service.installed", "process.created",
    /// "log.cleared", "sudo.command", "http.request", "bash.command".
    /// </summary>
    public required string EventKind { get; init; }

    /// <summary>Structured fields extracted by the parser — user, ip, service, etc.</summary>
    public IReadOnlyDictionary<string, string> Fields { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Optional numeric severity assigned by the source (Win EventLevel etc.).</summary>
    public int? NativeLevel { get; init; }

    /// <summary>Convenience lookup; returns null if missing.</summary>
    public string? GetField(string name) => Fields.TryGetValue(name, out var v) ? v : null;
}
