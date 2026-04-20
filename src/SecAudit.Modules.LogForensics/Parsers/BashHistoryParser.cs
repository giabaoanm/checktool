using System.Runtime.CompilerServices;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses ~/.bash_history / ~/.zsh_history. No per-line timestamps by default; if the
/// file was written with <c>HISTTIMEFORMAT</c>, lines are preceded by
/// <c>#&lt;unix-ts&gt;</c>. We honor both formats and fall back to the file mtime when
/// no hint is present so records remain timestamped for the BruteForce window logic.
/// </summary>
public sealed class BashHistoryParser : ILogParser
{
    public string Name => "bash-history";

    public bool CanHandle(RawLogFile file)
    {
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        return name.EndsWith("bash_history", StringComparison.Ordinal)
            || name.EndsWith("zsh_history", StringComparison.Ordinal)
            || name.EndsWith("_history", StringComparison.Ordinal);
    }

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        var fallbackTs = new DateTimeOffset(File.GetLastWriteTimeUtc(file.LocalPath), TimeSpan.Zero);
        long lineNo = 0;
        DateTimeOffset? pendingTs = null;

        using var sr = new StreamReader(file.LocalPath);
        string? line;
        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lineNo++;
            ct.ThrowIfCancellationRequested();

            if (line.StartsWith('#') && line.Length > 1
                && long.TryParse(line[1..].Trim(), out var epoch) && epoch > 0)
            {
                pendingTs = DateTimeOffset.FromUnixTimeSeconds(epoch);
                continue;
            }
            if (string.IsNullOrWhiteSpace(line)) { continue; }

            var ts = pendingTs ?? fallbackTs;
            pendingTs = null;

            var f = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Command"] = line.Trim()
            };

            yield return new LogRecord
            {
                Timestamp = ts,
                SourceFile = file.OriginalPath,
                SourceOffset = lineNo,
                Os = "linux",
                RawLine = line,
                EventKind = "bash.command",
                Fields = f
            };
        }
    }
}
