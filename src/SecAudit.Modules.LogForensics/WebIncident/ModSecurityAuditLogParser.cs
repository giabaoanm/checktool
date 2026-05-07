using System.Globalization;
using System.Text.RegularExpressions;

namespace SecAudit.Modules.LogForensics.WebIncident;

/// <summary>
/// Lightweight parser for ModSecurity audit logs in the legacy serial format
/// (sections A/B/F/H delimited by <c>--&lt;id&gt;-&lt;letter&gt;--</c>) and the
/// modern one-JSON-per-line format. Emits one <see cref="WebAttackTimelineEvent"/>
/// per blocked request, populated with the rule id + message that ModSec recorded.
///
/// <para>What we extract per transaction:</para>
/// <list type="bullet">
///   <item>Timestamp + client IP from section A</item>
///   <item>Method + path from section B's request line</item>
///   <item>Final status code from section F</item>
///   <item>OWASP CRS rule id + message from section H (multiple Messages → joined)</item>
/// </list>
/// </summary>
public static partial class ModSecurityAuditLogParser
{
    /// <summary>True when the file content looks like a ModSecurity audit log.</summary>
    public static bool LooksLikeAuditLog(string sample)
    {
        if (string.IsNullOrWhiteSpace(sample))
        {
            return false;
        }
        return SerialBoundaryRegex().IsMatch(sample)
            || sample.Contains("\"transaction\":", StringComparison.Ordinal)
            && sample.Contains("\"messages\":", StringComparison.Ordinal);
    }

    public static IReadOnlyList<WebAttackTimelineEvent> Parse(string content, string sourceFile)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(sourceFile);

        var events = new List<WebAttackTimelineEvent>();
        if (!LooksLikeAuditLog(content))
        {
            return events;
        }

        // Serial format: split by transaction id boundary.
        var transactions = SplitSerialTransactions(content);
        foreach (var tx in transactions)
        {
            var ev = ParseSerialTransaction(tx, sourceFile);
            if (ev is not null)
            {
                events.Add(ev);
            }
        }

        return events;
    }

    private static IReadOnlyList<string> SplitSerialTransactions(string content)
    {
        var matches = SerialBoundaryRegex().Matches(content);
        if (matches.Count == 0)
        {
            return Array.Empty<string>();
        }

        var spans = new List<string>();
        var currentTxId = string.Empty;
        var currentStart = -1;
        for (var i = 0; i < matches.Count; i++)
        {
            var m = matches[i];
            var txId = m.Groups["id"].Value;
            var section = m.Groups["section"].Value;
            if (section.Equals("A", StringComparison.OrdinalIgnoreCase))
            {
                currentTxId = txId;
                currentStart = m.Index;
            }
            else if (section.Equals("Z", StringComparison.OrdinalIgnoreCase)
                     && txId == currentTxId
                     && currentStart >= 0)
            {
                spans.Add(content[currentStart..(m.Index + m.Length)]);
                currentStart = -1;
            }
        }
        return spans;
    }

    private static WebAttackTimelineEvent? ParseSerialTransaction(string tx, string sourceFile)
    {
        var sectionA = ExtractSection(tx, "A");
        var sectionB = ExtractSection(tx, "B");
        var sectionF = ExtractSection(tx, "F");
        var sectionH = ExtractSection(tx, "H");

        var (timestamp, clientIp) = ParseSectionA(sectionA);
        var (method, path) = ParseSectionB(sectionB);
        var status = ParseStatus(sectionF);
        var (ruleId, message) = ExtractTopMessage(sectionH);
        var ua = ExtractHeader(sectionB, "User-Agent");

        if (string.IsNullOrEmpty(ruleId) && string.IsNullOrEmpty(message))
        {
            return null;
        }

        return new WebAttackTimelineEvent(
            Timestamp: timestamp,
            SourceIp: clientIp,
            Method: method,
            Path: path,
            StatusCode: status,
            UserAgent: ua,
            Rule: string.IsNullOrEmpty(ruleId)
                ? "ModSecurity:" + Truncate(message, 80)
                : "ModSecurity:" + ruleId,
            SourceFile: sourceFile,
            Raw: Truncate(message, 600));
    }

    private static string ExtractSection(string tx, string letter)
    {
        // Singleline so `.` spans newlines, but NOT Multiline — we want `$` to mean
        // end-of-input (so non-greedy `.*?` runs all the way to the next boundary or
        // the string end, not to the first `\n`). The leading `--` boundary is matched
        // by the explicit literal, no need for `^`-anchor with Multiline.
        var pattern = "--[^-\\r\\n]+-" + letter + "--\\r?\\n(?<body>.*?)(?=\\r?\\n--[^-\\r\\n]+-[A-Z]--|$)";
        var match = Regex.Match(tx, pattern, RegexOptions.Singleline, TimeSpan.FromSeconds(2));
        return match.Success ? match.Groups["body"].Value.Trim() : string.Empty;
    }

    private static (DateTimeOffset? Timestamp, string ClientIp) ParseSectionA(string sectionA)
    {
        if (string.IsNullOrEmpty(sectionA))
        {
            return (null, string.Empty);
        }
        // Format: [timestamp] tx-id client-ip client-port server-ip server-port
        var match = SectionARegex().Match(sectionA);
        if (!match.Success)
        {
            return (null, string.Empty);
        }
        DateTimeOffset? ts = DateTimeOffset.TryParseExact(
            match.Groups["ts"].Value,
            "dd/MMM/yyyy:HH:mm:ss zzz",
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out var parsed) ? parsed : null;
        return (ts, match.Groups["ip"].Value);
    }

    private static (string Method, string Path) ParseSectionB(string sectionB)
    {
        if (string.IsNullOrEmpty(sectionB))
        {
            return (string.Empty, string.Empty);
        }
        var firstLine = sectionB.Split('\n', 2)[0].Trim();
        var parts = firstLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? (parts[0], parts[1]) : (string.Empty, firstLine);
    }

    private static int? ParseStatus(string sectionF)
    {
        if (string.IsNullOrEmpty(sectionF))
        {
            return null;
        }
        var match = StatusRegex().Match(sectionF);
        return match.Success
               && int.TryParse(match.Groups["code"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var c)
            ? c
            : null;
    }

    private static (string RuleId, string Message) ExtractTopMessage(string sectionH)
    {
        if (string.IsNullOrEmpty(sectionH))
        {
            return (string.Empty, string.Empty);
        }
        var match = MessageRegex().Match(sectionH);
        if (!match.Success)
        {
            return (string.Empty, string.Empty);
        }
        return (match.Groups["id"].Value, match.Groups["msg"].Value);
    }

    private static string ExtractHeader(string sectionB, string headerName)
    {
        var pattern = "^" + Regex.Escape(headerName) + @":\s*(?<v>.+)$";
        var match = Regex.Match(sectionB, pattern,
            RegexOptions.Multiline | RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(2));
        return match.Success ? match.Groups["v"].Value.Trim() : string.Empty;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    [GeneratedRegex(@"^--(?<id>[A-Za-z0-9]+)-(?<section>[A-Z])--\s*$", RegexOptions.Multiline)]
    private static partial Regex SerialBoundaryRegex();

    [GeneratedRegex(@"\[(?<ts>[^\]]+)\]\s+\S+\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})")]
    private static partial Regex SectionARegex();

    [GeneratedRegex(@"HTTP/\d\.\d\s+(?<code>\d{3})\b")]
    private static partial Regex StatusRegex();

    [GeneratedRegex(@"\[id\s+""(?<id>\d+)""\][^\[]*\[msg\s+""(?<msg>[^""]+)""\]")]
    private static partial Regex MessageRegex();
}
