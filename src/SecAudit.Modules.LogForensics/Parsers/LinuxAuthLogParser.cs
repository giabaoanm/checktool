using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS). Both
/// share the rsyslog format:
///   <c>Apr 20 10:23:44 host sshd[12345]: Failed password for root from 1.2.3.4 port 51234 ssh2</c>
///
/// Kinds emitted:
///   logon.failed  (sshd "Failed password", "Invalid user", PAM auth failure)
///   logon.success (sshd "Accepted password", "Accepted publickey")
///   sudo.command  (sudo "COMMAND=...")
///   sudo.failed   (sudo "authentication failure")
///   account.created (useradd)
///   log.cleared   (rsyslogd stop / truncate markers)
/// </summary>
public sealed partial class LinuxAuthLogParser : ILogParser
{
    public string Name => "linux-auth";

    public bool CanHandle(RawLogFile file)
    {
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        if (name.StartsWith("auth", StringComparison.Ordinal)) { return true; }
        if (name.StartsWith("secure", StringComparison.Ordinal)) { return true; }
        return false;
    }

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        // rsyslog default lacks year; we use file mtime year as best effort.
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

    [GeneratedRegex(@"from\s+(?<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?<port>\d+))?", RegexOptions.Compiled)]
    private static partial Regex FromIp();

    [GeneratedRegex(@"for\s+(?:invalid user\s+)?(?<user>\S+)\s+from", RegexOptions.Compiled)]
    private static partial Regex ForUser();

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
        var (kind, fields) = ClassifyMessage(svc, msg);
        if (kind is null) { return null; }

        fields["_service"] = svc;
        fields["_host"] = m.Groups["host"].Value;
        if (m.Groups["pid"].Success) { fields["_pid"] = m.Groups["pid"].Value; }

        return new LogRecord
        {
            Timestamp = ts,
            SourceFile = sourceFile,
            SourceOffset = lineNo,
            Os = "linux",
            RawLine = line,
            EventKind = kind,
            Fields = fields
        };
    }

    private static (string? kind, Dictionary<string, string> fields) ClassifyMessage(string svc, string msg)
    {
        var f = new Dictionary<string, string>(StringComparer.Ordinal);

        if (svc.Equals("sshd", StringComparison.OrdinalIgnoreCase))
        {
            // SSH failure patterns
            if (msg.StartsWith("Failed password", StringComparison.Ordinal)
                || msg.StartsWith("Invalid user", StringComparison.Ordinal)
                || msg.Contains("authentication failure", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("Connection closed by authenticating user", StringComparison.OrdinalIgnoreCase))
            {
                ExtractFromIpUser(msg, f);
                return ("logon.failed", f);
            }

            // SSH success
            if (msg.StartsWith("Accepted password", StringComparison.Ordinal)
                || msg.StartsWith("Accepted publickey", StringComparison.Ordinal)
                || msg.StartsWith("Accepted keyboard-interactive", StringComparison.Ordinal))
            {
                ExtractFromIpUser(msg, f);
                f["Method"] = msg.Contains("publickey", StringComparison.Ordinal) ? "publickey"
                    : msg.Contains("password", StringComparison.Ordinal) ? "password" : "other";
                return ("logon.success", f);
            }
        }

        if (svc.StartsWith("sudo", StringComparison.OrdinalIgnoreCase))
        {
            if (msg.Contains("authentication failure", StringComparison.OrdinalIgnoreCase))
            {
                var user = ExtractBetween(msg, "user=", " ");
                if (user is not null) { f["TargetUserName"] = user; }
                return ("sudo.failed", f);
            }
            if (msg.Contains("COMMAND=", StringComparison.Ordinal))
            {
                var user = ExtractBetween(msg, " : ", " :");
                var cmd = ExtractAfter(msg, "COMMAND=");
                if (user is not null) { f["SourceUser"] = user; }
                if (cmd is not null) { f["Command"] = cmd; }
                return ("sudo.command", f);
            }
        }

        if (svc.Equals("useradd", StringComparison.OrdinalIgnoreCase)
            && msg.StartsWith("new user", StringComparison.OrdinalIgnoreCase))
        {
            var name = ExtractBetween(msg, "name=", ",");
            if (name is not null) { f["TargetUserName"] = name; }
            return ("account.created", f);
        }

        if (svc.StartsWith("rsyslog", StringComparison.OrdinalIgnoreCase)
            && msg.Contains("start", StringComparison.OrdinalIgnoreCase))
        {
            // approximate "log.cleared" signal if service restarted mid-day (gap)
            return ("log.cleared", f);
        }
        return (null, f);
    }

    private static void ExtractFromIpUser(string msg, Dictionary<string, string> f)
    {
        var ipM = FromIp().Match(msg);
        if (ipM.Success)
        {
            f["IpAddress"] = ipM.Groups["ip"].Value;
            if (ipM.Groups["port"].Success) { f["Port"] = ipM.Groups["port"].Value; }
        }
        var userM = ForUser().Match(msg);
        if (userM.Success)
        {
            f["TargetUserName"] = userM.Groups["user"].Value;
        }
    }

    private static string? ExtractBetween(string haystack, string start, string end)
    {
        int i = haystack.IndexOf(start, StringComparison.Ordinal);
        if (i < 0) { return null; }
        i += start.Length;
        int j = haystack.IndexOf(end, i, StringComparison.Ordinal);
        if (j < 0) { return haystack[i..]; }
        return haystack[i..j];
    }

    private static string? ExtractAfter(string haystack, string marker)
    {
        int i = haystack.IndexOf(marker, StringComparison.Ordinal);
        return i < 0 ? null : haystack[(i + marker.Length)..];
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
