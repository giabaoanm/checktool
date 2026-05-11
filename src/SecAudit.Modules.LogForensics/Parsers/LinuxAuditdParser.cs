using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Parses Linux auditd log files (typically <c>/var/log/audit/audit.log</c>).
/// auditd records are line-oriented with <c>type=&lt;TYPE&gt; msg=audit(epoch:serial): key=val …</c>
/// — we focus on the three types most useful for IR triage:
///
/// <list type="bullet">
///   <item><c>type=EXECVE</c> — full <c>argc=N a0="..." a1="..."</c> command line that
///         was actually executed (much higher fidelity than sudo.command which only
///         records what the user typed at sudo).</item>
///   <item><c>type=PATH</c> — file path touched by the syscall (writes to .locked
///         files, ransomware encryption evidence).</item>
///   <item><c>type=SYSCALL</c> — header carrying euid/uid/exe + key tag, used to
///         label PATH/EXECVE records belonging to the same audit transaction.</item>
/// </list>
///
/// <para>Emitted event kinds:</para>
/// <list type="bullet">
///   <item><c>audit.execve</c> — fields: <c>Command</c> (reassembled argv),
///         <c>Exe</c>, <c>SourceUser</c> (uid).</item>
///   <item><c>audit.path</c> — fields: <c>Path</c> (file touched), <c>Op</c>
///         (CREATE/DELETE/NORMAL — heuristic from PATH name).</item>
/// </list>
/// </summary>
public sealed partial class LinuxAuditdParser : ILogParser
{
    public string Name => "linux-auditd";

    public bool CanHandle(RawLogFile file)
    {
        var name = Path.GetFileName(file.LocalPath).ToLowerInvariant();
        // Match: audit.log, audit.log.1, audit.log.1.gz (post-decompress), AUDIT.LOG.
        // Avoid matching auth.log (different parser).
        return name.StartsWith("audit", StringComparison.Ordinal)
            && (name.Equals("audit.log", StringComparison.Ordinal)
                || name.StartsWith("audit.log.", StringComparison.Ordinal)
                || name.StartsWith("audit-", StringComparison.Ordinal));
    }

    public async IAsyncEnumerable<LogRecord> ParseAsync(
        RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        long lineNo = 0;
        using var sr = new StreamReader(file.LocalPath);
        string? line;
        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lineNo++;
            ct.ThrowIfCancellationRequested();
            var rec = TryParseLine(line, lineNo, file.OriginalPath);
            if (rec is not null) { yield return rec; }
        }
    }

    [GeneratedRegex(@"^type=(?<type>\w+)\s+msg=audit\((?<epoch>\d+(?:\.\d+)?):(?<serial>\d+)\)\s*:\s*(?<rest>.*)$",
        RegexOptions.Compiled)]
    private static partial Regex AuditLine();

    [GeneratedRegex(@"\ba(?<i>\d+)=(?<v>(?:""[^""]*""|\S+))",
        RegexOptions.Compiled)]
    private static partial Regex ExecveArg();

    [GeneratedRegex(@"\b(?<k>\w+)=(?<v>(?:""[^""]*""|\S+))",
        RegexOptions.Compiled)]
    private static partial Regex KeyValue();

    private static LogRecord? TryParseLine(string line, long lineNo, string sourceFile)
    {
        if (string.IsNullOrWhiteSpace(line)) { return null; }
        var m = AuditLine().Match(line);
        if (!m.Success) { return null; }

        var type = m.Groups["type"].Value;
        // Only the three types we care about — skip noisy CWD/PROCTITLE/etc.
        if (type != "EXECVE" && type != "PATH" && type != "SYSCALL")
        {
            return null;
        }

        var epoch = m.Groups["epoch"].Value;
        var rest = m.Groups["rest"].Value;
        if (!double.TryParse(epoch, NumberStyles.Float, CultureInfo.InvariantCulture, out var sec))
        {
            return null;
        }
        var ts = DateTimeOffset.FromUnixTimeMilliseconds((long)(sec * 1000));

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        string? kind = null;

        switch (type)
        {
            case "EXECVE":
                kind = "audit.execve";
                fields["Command"] = ReassembleExecveArgs(rest);
                break;

            case "PATH":
                kind = "audit.path";
                var name = ExtractKv(rest, "name")?.Trim('"');
                if (string.IsNullOrEmpty(name)) { return null; }
                fields["Path"] = name;
                fields["Op"] = ClassifyPathOp(rest, name);
                var nametype = ExtractKv(rest, "nametype");
                if (nametype is not null) { fields["NameType"] = nametype; }
                break;

            case "SYSCALL":
                // Carry interesting metadata so downstream rules can correlate.
                kind = "audit.syscall";
                var exe = ExtractKv(rest, "exe")?.Trim('"');
                var uid = ExtractKv(rest, "uid");
                var euid = ExtractKv(rest, "euid");
                var key = ExtractKv(rest, "key")?.Trim('"');
                if (exe is not null) { fields["Exe"] = exe; fields["Command"] = exe; }
                if (uid is not null) { fields["SourceUser"] = "uid:" + uid; }
                if (euid is not null) { fields["EffectiveUser"] = "euid:" + euid; }
                if (key is not null && key != "(null)") { fields["AuditKey"] = key; }
                break;
        }

        if (kind is null) { return null; }

        return new LogRecord
        {
            Timestamp = ts,
            SourceFile = sourceFile,
            SourceOffset = lineNo,
            Os = "linux",
            EventKind = kind,
            RawLine = line,
            Fields = fields
        };
    }

    /// <summary>
    /// Reconstruct <c>argc=2 a0="cp" a1="/tmp/x" a2="/usr/local/bin/x"</c> back into
    /// the human-readable command line. Strips quotes, joins with spaces, in argv order.
    /// </summary>
    private static string ReassembleExecveArgs(string rest)
    {
        var parts = new SortedDictionary<int, string>();
        foreach (Match m in ExecveArg().Matches(rest))
        {
            if (!int.TryParse(m.Groups["i"].Value, out var i)) { continue; }
            parts[i] = m.Groups["v"].Value.Trim('"');
        }
        return parts.Count == 0 ? rest : string.Join(' ', parts.Values);
    }

    private static string? ExtractKv(string rest, string key)
    {
        // Anchored at word boundary to avoid matching "auid" when asking for "uid".
        var pattern = "\\b" + Regex.Escape(key) + @"=(?<v>(?:""[^""]*""|\S+))";
        var m = Regex.Match(rest, pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
        return m.Success ? m.Groups["v"].Value : null;
    }

    private static string ClassifyPathOp(string rest, string name)
    {
        // nametype values: NORMAL, CREATE, DELETE, PARENT, UNKNOWN.
        var nt = ExtractKv(rest, "nametype");
        if (nt is not null) { return nt; }

        // Heuristic fallback when nametype is absent on older audit versions:
        // .locked / .encrypted suffix → very likely CREATE in ransomware context.
        if (name.EndsWith(".locked", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".encrypted", StringComparison.OrdinalIgnoreCase))
        {
            return "CREATE";
        }
        return "NORMAL";
    }
}
