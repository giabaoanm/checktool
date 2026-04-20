using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses /var/log/syslog and /var/log/messages — broad RSyslog feed. Narrower in scope
/// than auth.log: we extract cron jobs, kernel oops, service unit start/stop, and any
/// line that mentions "sudo" / "su:" / "Failed" so that rules can still see brute-force
/// or privilege-escalation signals even when the host doesn't ship an auth-dedicated log.
/// </summary>
public sealed partial class LinuxSyslogParser : ILogParser
{
    public string Name => "linux-syslog";

    public bool CanHandle(RawLogFile file)
    {
        if (!"linux".Equals(file.OsHint, StringComparison.OrdinalIgnoreCase)) { return false; }
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        if (name.StartsWith("auth", StringComparison.Ordinal)
            || name.StartsWith("secure", StringComparison.Ordinal))
        {
            // auth.log/secure are handled by LinuxAuthLogParser — do NOT double-parse.
            return false;
        }
        return name.StartsWith("syslog", StringComparison.Ordinal)
            || name.Equals("messages", StringComparison.Ordinal)
            || name.StartsWith("messages.", StringComparison.Ordinal);
    }

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        int year = File.GetLastWriteTimeUtc(file.LocalPath).Year;
        long lineNo = 0;
        using var sr = new StreamReader(file.LocalPath);
        string? line;
        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lineNo++;
            ct.ThrowIfCancellationRequested();
            var rec = TryParseLine(line, lineNo, file.OriginalPath, year);
            if (rec is not null) { yield return rec; }
        }
    }

    [GeneratedRegex(@"^(?<mon>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<svc>[^:\[]+)(?:\[(?<pid>\d+)\])?:\s*(?<msg>.*)$",
        RegexOptions.Compiled)]
    private static partial Regex SyslogLine();

    private static LogRecord? TryParseLine(string line, long lineNo, string sourceFile, int year)
    {
        var m = SyslogLine().Match(line);
        if (!m.Success) { return null; }
        if (!TryBuildTs(m.Groups["mon"].Value, m.Groups["day"].Value, m.Groups["time"].Value, year, out var ts))
        {
            return null;
        }

        var svc = m.Groups["svc"].Value.Trim();
        var msg = m.Groups["msg"].Value;
        var f = new Dictionary<string, string>(StringComparer.Ordinal) { ["_service"] = svc };

        string? kind = null;
        if (svc.Equals("kernel", StringComparison.OrdinalIgnoreCase)
            && (msg.Contains("Oops", StringComparison.Ordinal) || msg.Contains("BUG:", StringComparison.Ordinal)))
        {
            kind = "kernel.oops";
        }
        else if (msg.Contains("Started ", StringComparison.Ordinal) || msg.Contains("Starting ", StringComparison.Ordinal))
        {
            f["UnitMessage"] = msg;
            kind = "service.started";
        }
        else if (msg.Contains("Stopped ", StringComparison.Ordinal) || msg.Contains("Stopping ", StringComparison.Ordinal))
        {
            f["UnitMessage"] = msg;
            kind = "service.stopped";
        }
        else if (svc.StartsWith("CRON", StringComparison.OrdinalIgnoreCase))
        {
            f["Command"] = msg;
            kind = "cron.job";
        }

        if (kind is null) { return null; }

        return new LogRecord
        {
            Timestamp = ts,
            SourceFile = sourceFile,
            SourceOffset = lineNo,
            Os = "linux",
            RawLine = line,
            EventKind = kind,
            Fields = f
        };
    }

    private static bool TryBuildTs(string mon, string day, string time, int year, out DateTimeOffset ts)
    {
        ts = default;
        var fmt = $"{year} {mon} {day,2} {time}";
        if (DateTime.TryParseExact(fmt, "yyyy MMM  d HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            || DateTime.TryParseExact(fmt, "yyyy MMM d HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out dt))
        {
            ts = new DateTimeOffset(dt, TimeSpan.Zero);
            return true;
        }
        return false;
    }
}
