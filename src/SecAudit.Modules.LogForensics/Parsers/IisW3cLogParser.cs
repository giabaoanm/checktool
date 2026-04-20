using System.Globalization;
using System.Runtime.CompilerServices;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses IIS W3C Extended Log Format. The column list is declared per-file via a
/// <c>#Fields:</c> header line, so we build the index dynamically then emit a
/// <c>http.request</c> record per data row — consumable by VulnScanRule.
/// </summary>
public sealed class IisW3cLogParser : ILogParser
{
    public string Name => "iis-w3c";

    public bool CanHandle(RawLogFile file)
    {
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        // IIS default: u_ex<YYMMDD>.log; also W3SVC*.log.
        return name.StartsWith("u_ex", StringComparison.Ordinal)
            || name.StartsWith("u_in", StringComparison.Ordinal)
            || name.StartsWith("w3svc", StringComparison.Ordinal);
    }

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        using var sr = new StreamReader(file.LocalPath);
        string? line;
        long lineNo = 0;
        string[]? cols = null;

        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lineNo++;
            ct.ThrowIfCancellationRequested();
            if (line.Length == 0) { continue; }

            if (line.StartsWith("#Fields:", StringComparison.Ordinal))
            {
                cols = line[8..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                continue;
            }
            if (line.StartsWith('#')) { continue; }
            if (cols is null) { continue; } // data before header — skip

            var parts = line.Split(' ');
            if (parts.Length < cols.Length) { continue; }

            var f = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int i = 0; i < cols.Length; i++)
            {
                f[cols[i]] = parts[i];
            }

            if (!TryBuildTs(f, out var ts)) { continue; }

            // Normalize common field names for downstream rules.
            if (f.TryGetValue("c-ip", out var cip)) { f["IpAddress"] = cip; }
            if (f.TryGetValue("cs-uri-stem", out var uri))
            {
                if (f.TryGetValue("cs-uri-query", out var qs) && qs != "-")
                {
                    f["Uri"] = uri + "?" + qs;
                }
                else
                {
                    f["Uri"] = uri;
                }
            }
            if (f.TryGetValue("cs(User-Agent)", out var ua)) { f["UserAgent"] = ua.Replace('+', ' '); }
            if (f.TryGetValue("sc-status", out var sc)) { f["Status"] = sc; }
            if (f.TryGetValue("cs-method", out var mth)) { f["Method"] = mth; }

            yield return new LogRecord
            {
                Timestamp = ts,
                SourceFile = file.OriginalPath,
                SourceOffset = lineNo,
                Os = "windows",
                RawLine = line,
                EventKind = "http.request",
                Fields = f
            };
        }
    }

    private static bool TryBuildTs(Dictionary<string, string> f, out DateTimeOffset ts)
    {
        ts = default;
        if (!f.TryGetValue("date", out var d)) { return false; }
        if (!f.TryGetValue("time", out var t)) { return false; }
        if (!DateTime.TryParseExact($"{d} {t}", "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            return false;
        }
        ts = new DateTimeOffset(dt, TimeSpan.Zero);
        return true;
    }
}
