using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses nginx / Apache "combined" access log format:
///   <c>127.0.0.1 - - [20/Apr/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 200 512 "-" "curl/8"</c>
/// Emits <c>http.request</c> records. Same parser works for Apache combined logs — both
/// servers ship this as the default.
/// </summary>
public sealed partial class NginxAccessLogParser : ILogParser
{
    public string Name => "nginx-combined";

    public bool CanHandle(RawLogFile file)
    {
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        if (name.Contains("access", StringComparison.Ordinal))
        {
            // Could be IIS too — disambiguate by extension: IIS uses .log but starts with u_.
            if (name.StartsWith("u_", StringComparison.Ordinal)) { return false; }
            return true;
        }
        return false;
    }

    [GeneratedRegex(@"^(?<ip>\S+)\s+\S+\s+(?<user>\S+)\s+\[(?<ts>[^\]]+)\]\s+""(?<method>[A-Z]+)\s+(?<uri>[^\s""]+)[^""]*""\s+(?<status>\d{3})\s+(?<bytes>\d+|-)\s+""(?<referer>[^""]*)""\s+""(?<ua>[^""]*)""",
        RegexOptions.Compiled)]
    private static partial Regex Combined();

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        long lineNo = 0;
        using var sr = new StreamReader(file.LocalPath);
        string? line;
        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lineNo++;
            ct.ThrowIfCancellationRequested();
            var m = Combined().Match(line);
            if (!m.Success) { continue; }
            if (!TryParseTs(m.Groups["ts"].Value, out var ts)) { continue; }

            var f = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["IpAddress"] = m.Groups["ip"].Value,
                ["Method"] = m.Groups["method"].Value,
                ["Uri"] = m.Groups["uri"].Value,
                ["Status"] = m.Groups["status"].Value,
                ["UserAgent"] = m.Groups["ua"].Value,
                ["Referer"] = m.Groups["referer"].Value
            };
            if (m.Groups["user"].Value != "-") { f["TargetUserName"] = m.Groups["user"].Value; }

            yield return new LogRecord
            {
                Timestamp = ts,
                SourceFile = file.OriginalPath,
                SourceOffset = lineNo,
                Os = file.OsHint.Equals("windows", StringComparison.OrdinalIgnoreCase) ? "windows" : "linux",
                RawLine = line,
                EventKind = "http.request",
                Fields = f
            };
        }
    }

    private static bool TryParseTs(string raw, out DateTimeOffset ts)
    {
        // e.g. "20/Apr/2026:10:00:00 +0000"
        if (DateTimeOffset.TryParseExact(raw, "dd/MMM/yyyy:HH:mm:ss zzz", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out ts))
        {
            return true;
        }
        if (DateTimeOffset.TryParseExact(raw, "dd/MMM/yyyy:HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out ts))
        {
            return true;
        }
        return false;
    }
}
