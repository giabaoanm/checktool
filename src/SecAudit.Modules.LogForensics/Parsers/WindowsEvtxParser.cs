using System.Diagnostics.Eventing.Reader;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Reads Windows *.evtx via EventLogReader. Maps a curated set of Event IDs to our
/// canonical <see cref="LogRecord.EventKind"/> taxonomy so rules can match by kind.
///
/// Intentionally does NOT ingest every event — we want fast iteration on O(millions)
/// security logs, so we skip IDs we never act on.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEvtxParser : ILogParser
{
    public string Name => "windows-evtx";

    public bool CanHandle(RawLogFile file)
        => string.Equals(Path.GetExtension(file.LocalPath), ".evtx", StringComparison.OrdinalIgnoreCase);

    // Curated ID -> kind map. Anything not listed is ignored.
    private static readonly Dictionary<int, string> IdToKind = new()
    {
        { 4624, "logon.success" },
        { 4625, "logon.failed" },
        { 4634, "logon.logoff" },
        { 4648, "logon.explicit" },
        { 4672, "privilege.assigned" },
        { 4688, "process.created" },
        { 4697, "service.installed" },
        { 4698, "task.created" },
        { 4720, "account.created" },
        { 4732, "group.memberadded" },
        { 1102, "log.cleared" },
        { 7045, "service.installed" },   // System channel variant
        { 104,  "log.cleared" },          // System channel variant
        { 1,    "sysmon.process" },
        { 3,    "sysmon.network" },
        { 11,   "sysmon.filecreate" },
        { 13,   "sysmon.regset" },
        { 4104, "powershell.scriptblock" }
    };

    public async IAsyncEnumerable<LogRecord> ParseAsync(RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        // EventLogReader is synchronous; yield periodically to keep UI responsive.
        var q = new EventLogQuery(file.LocalPath, PathType.FilePath) { ReverseDirection = false };
        using var reader = new EventLogReader(q);
        int since = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            EventRecord? evt;
            try { evt = reader.ReadEvent(); }
            catch (EventLogException) { yield break; }
            if (evt is null) { yield break; }

            using (evt)
            {
                if (!IdToKind.TryGetValue(evt.Id, out var kind))
                {
                    goto NEXT;
                }

                var fields = ExtractFields(evt);
                var raw = TryFormatDescription(evt);
                yield return new LogRecord
                {
                    Timestamp = new DateTimeOffset(
                        (evt.TimeCreated ?? DateTime.UtcNow).ToUniversalTime(), TimeSpan.Zero),
                    SourceFile = file.OriginalPath,
                    SourceOffset = evt.RecordId ?? 0,
                    Os = "windows",
                    RawLine = raw,
                    EventKind = kind,
                    Fields = fields,
                    NativeLevel = evt.Level
                };
            }

            NEXT:
            if (++since >= 500)
            {
                since = 0;
                await Task.Yield();
            }
        }
    }

    private static Dictionary<string, string> ExtractFields(EventRecord evt)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["EventId"] = evt.Id.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Provider"] = evt.ProviderName ?? string.Empty,
            ["Channel"] = evt.LogName ?? string.Empty
        };
        if (!string.IsNullOrEmpty(evt.MachineName)) { dict["MachineName"] = evt.MachineName; }

        // Map well-known properties by event ID.
        try
        {
            var props = evt.Properties;
            switch (evt.Id)
            {
                case 4624:
                case 4625:
                case 4648:
                case 4634:
                case 4672:
                    // TargetUserName, TargetDomainName, LogonType, IpAddress positions vary
                    // but can be read from the rendered XML below. We use a simple XML parse
                    // for correctness across both Security and forwarded channels.
                    break;
                case 4688:
                    // NewProcessName index 5 in Security 10.0+
                    break;
            }

            // Fallback: parse XML once to extract all EventData/Data Name=Value pairs.
            var xml = evt.ToXml();
            ParseEventDataXml(xml, dict);
            _ = props;
        }
        catch
        {
            // Ignore extraction failures — raw line + kind still reach rules.
        }
        return dict;
    }

    private static void ParseEventDataXml(string xml, Dictionary<string, string> dict)
    {
        // Tiny hand-rolled extractor for <Data Name="X">Y</Data> — faster than XmlReader
        // instantiation per event and good enough since EVTX XML is well-formed.
        int i = 0;
        while (i < xml.Length)
        {
            int tagStart = xml.IndexOf("<Data Name=\"", i, StringComparison.Ordinal);
            if (tagStart < 0) { break; }
            int nameStart = tagStart + "<Data Name=\"".Length;
            int nameEnd = xml.IndexOf('"', nameStart);
            if (nameEnd < 0) { break; }
            int valStart = xml.IndexOf('>', nameEnd) + 1;
            int valEnd = xml.IndexOf("</Data>", valStart, StringComparison.Ordinal);
            if (valEnd < 0) { break; }
            var name = xml[nameStart..nameEnd];
            var value = System.Net.WebUtility.HtmlDecode(xml[valStart..valEnd]);
            dict[name] = value;
            i = valEnd + 7;
        }
    }

    private static string TryFormatDescription(EventRecord evt)
    {
        try
        {
            return evt.FormatDescription() ?? $"EventID={evt.Id}";
        }
        catch
        {
            return $"EventID={evt.Id} (template unavailable)";
        }
    }
}
