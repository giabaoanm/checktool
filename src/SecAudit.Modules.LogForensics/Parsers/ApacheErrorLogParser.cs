using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses Apache / nginx error.log lines, which use a different format from access.log:
///   <c>[Sun Apr 20 10:00:00.123456 2026] [core:error] [pid 1234:tid 5678] [client 1.2.3.4:5678] File does not exist...</c>
/// We extract the timestamp, log level, client IP, and message — enough for
/// "5xx flood" or "auth failure" rule variations we may add later.
/// </summary>
public sealed partial class ApacheErrorLogParser : ILogParser
{
    public string Name => "apache-error";

    public bool CanHandle(RawLogFile file)
    {
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        return name.Contains("error", StringComparison.Ordinal)
            && !name.StartsWith("u_", StringComparison.Ordinal) // IIS u_ex/u_in
            && !name.StartsWith("w3svc", StringComparison.Ordinal);
    }

    [GeneratedRegex(@"^\[(?<ts>[^\]]+)\]\s+\[(?<module>[^:\]]+):(?<level>[^\]]+)\]\s+(?:\[pid [^\]]+\]\s+)?(?:\[client\s+(?<ip>[^\]:]+)(?::\d+)?\]\s+)?(?<msg>.*)$",
        RegexOptions.Compiled)]
    private static partial Regex ErrorLine();

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        long lineNo = 0;
        using var sr = new StreamReader(file.LocalPath);
        string? line;
        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lineNo++;
            ct.ThrowIfCancellationRequested();
            var m = ErrorLine().Match(line);
            if (!m.Success) { continue; }
            if (!TryParseTs(m.Groups["ts"].Value, out var ts)) { continue; }

            var f = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Module"] = m.Groups["module"].Value,
                ["Level"] = m.Groups["level"].Value,
                ["Message"] = m.Groups["msg"].Value
            };
            if (m.Groups["ip"].Success) { f["IpAddress"] = m.Groups["ip"].Value; }

            yield return new LogRecord
            {
                Timestamp = ts,
                SourceFile = file.OriginalPath,
                SourceOffset = lineNo,
                Os = file.OsHint.Equals("windows", StringComparison.OrdinalIgnoreCase) ? "windows" : "linux",
                RawLine = line,
                EventKind = "http.error",
                Fields = f
            };
        }
    }

    private static bool TryParseTs(string raw, out DateTimeOffset ts)
    {
        // Common forms:
        //   "Sun Apr 20 10:00:00.123456 2026"  (Apache default)
        //   "Sun Apr 20 10:00:00 2026"         (no microseconds)
        //   "2026/04/20 10:00:00"              (nginx default)
        if (DateTimeOffset.TryParseExact(raw, "ddd MMM d HH:mm:ss.ffffff yyyy", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out ts)) { return true; }
        if (DateTimeOffset.TryParseExact(raw, "ddd MMM  d HH:mm:ss.ffffff yyyy", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out ts)) { return true; }
        if (DateTimeOffset.TryParseExact(raw, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out ts)) { return true; }
        if (DateTimeOffset.TryParseExact(raw, "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out ts)) { return true; }
        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out ts))
        {
            return true;
        }
        return false;
    }
}
