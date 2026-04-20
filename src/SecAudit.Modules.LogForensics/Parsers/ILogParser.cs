using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Turns a single log file into a stream of normalized <see cref="LogRecord"/>s. Each
/// parser implements <see cref="CanHandle"/> to claim files by extension/heuristics so
/// the engine can dispatch without hard-coding per-format routing.
/// </summary>
public interface ILogParser
{
    string Name { get; }

    /// <summary>Quick test (extension + optional header sniff) to claim a file.</summary>
    bool CanHandle(RawLogFile file);

    IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, CancellationToken ct);
}
