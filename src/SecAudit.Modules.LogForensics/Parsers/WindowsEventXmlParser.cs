using System.Globalization;
using System.Runtime.CompilerServices;
using System.Xml;
using System.Xml.Linq;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Sources;

namespace SecAudit.Modules.LogForensics.Parsers;

/// <summary>
/// Đọc Windows Event Log đã export dạng XML (<c>wevtutil qe &lt;channel&gt; /f:XML</c>)
/// hoặc viết tay cho test/demo. Giải quyết vấn đề <c>.evtx</c> là định dạng nhị
/// phân proprietary — gần như không thể hand-craft cho fixture, trong khi XML
/// export được dùng rộng rãi trong SOC (thu thập từ máy không cài agent forwarder).
///
/// <para>
/// Hỗ trợ 2 thể loại root:
/// <list type="bullet">
///   <item>Một tệp bọc <c>&lt;Events&gt;…&lt;/Events&gt;</c> chứa nhiều <c>&lt;Event&gt;</c>.</item>
///   <item>Hoặc một "list" <c>&lt;Event&gt;</c> concatenated (mặc định <c>wevtutil</c>
///   không emit wrapper — ta gói lại bằng reader forgiving).</item>
/// </list>
/// </para>
///
/// Output <see cref="LogRecord.EventKind"/> GIỐNG HỆT <see cref="WindowsEvtxParser"/>
/// để các rule hiện hữu hoạt động không cần sửa.
///
/// <para>
/// Implementation notes — chọn <see cref="XDocument"/> thay vì <see cref="XmlReader"/>:
/// EVTX XML events trung bình chỉ vài KB mỗi event, file log forensics trung bình
/// &lt; 10 MB. XDocument load cả file vào DOM thì tốn RAM nhưng loại bỏ hoàn toàn
/// các bẫy positioning của forward-only reader (đáng chú ý là
/// <c>ReadElementContentAsString</c> tự động advance reader, khiến outer while loop
/// skip element kế tiếp — bug cổ điển tốn giờ debug). Ta ưu tiên correctness hơn
/// perf trong module forensics offline.
/// </para>
/// </summary>
public sealed class WindowsEventXmlParser : ILogParser
{
    public string Name => "windows-event-xml";

    public bool CanHandle(RawLogFile file)
    {
        // Chấp nhận mọi .xml có tên chứa "sysmon", "security", "winevt", "wevt",
        // "system", "application" — analyst đặt tên rõ nghĩa cho fixture. Tránh
        // đụng vào .xml của ứng dụng khác trong cùng thư mục.
        if (!string.Equals(Path.GetExtension(file.LocalPath), ".xml", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var name = Path.GetFileNameWithoutExtension(file.LocalPath);
        return name.Contains("sysmon",   StringComparison.OrdinalIgnoreCase)
            || name.Contains("security", StringComparison.OrdinalIgnoreCase)
            || name.Contains("winevt",   StringComparison.OrdinalIgnoreCase)
            || name.Contains("wevt",     StringComparison.OrdinalIgnoreCase)
            || name.Contains("evtx",     StringComparison.OrdinalIgnoreCase)
            || name.Contains("winlog",   StringComparison.OrdinalIgnoreCase)
            || name.Contains("evlog",    StringComparison.OrdinalIgnoreCase);
    }

    // Dùng chung bảng map với WindowsEvtxParser — duplicate để 2 parser có thể
    // chạy trên môi trường không có System.Diagnostics.Eventing.Reader (Linux build).
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
        { 7045, "service.installed" },
        { 104,  "log.cleared" },
        { 4104, "powershell.scriptblock" }
    };

    private static readonly Dictionary<int, string> SysmonIdToKind = new()
    {
        { 1,  "sysmon.process" },
        { 3,  "sysmon.network" },
        { 7,  "sysmon.imageload" },
        { 8,  "sysmon.createremotethread" },
        { 10, "sysmon.processaccess" },
        { 11, "sysmon.filecreate" },
        { 13, "sysmon.regset" },
        { 17, "sysmon.pipecreate" },
        { 18, "sysmon.pipeconnect" },
        { 19, "sysmon.wmifilter" },
        { 20, "sysmon.wmiconsumer" },
        { 21, "sysmon.wmibinding" },
        { 22, "sysmon.dnsquery" }
    };

    private const string SysmonProviderPrefix = "Microsoft-Windows-Sysmon";

    public async IAsyncEnumerable<LogRecord> ParseAsync(
        RawLogFile file, [EnumeratorCancellation] CancellationToken ct)
    {
        var records = new List<LogRecord>();
        await Task.Run(() =>
        {
            // Nạp toàn bộ file vào string rồi wrap trong pseudo-root để XDocument xử
            // lý được các file không có wrapper. File log forensics trung bình < 10 MB
            // nên nạp vào RAM đơn giản hơn streaming từng Event tag.
            string content = File.ReadAllText(file.LocalPath);
            string trimmed = content.TrimStart('\uFEFF', ' ', '\t', '\r', '\n');

            // Bỏ prolog XML (<?xml …?>) nếu có — nó phải nằm đầu file, nhưng ta wrap
            // bằng <Events> nên sẽ đặt sai vị trí. Xử lý đơn giản: tách prolog + wrap phần thân.
            if (trimmed.StartsWith("<?xml", StringComparison.Ordinal))
            {
                int endProlog = trimmed.IndexOf("?>", StringComparison.Ordinal);
                if (endProlog > 0) { trimmed = trimmed[(endProlog + 2)..].TrimStart(); }
            }

            string wrapped = trimmed.Contains("<Events", StringComparison.Ordinal)
                ? trimmed
                : "<Events>" + trimmed + "</Events>";

            // DtdProcessing = Prohibit trên reader wrapped bên trong XDocument.Load.
            XDocument doc;
            using (var sr = new StringReader(wrapped))
            using (var reader = XmlReader.Create(sr, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true
            }))
            {
                doc = XDocument.Load(reader);
            }

            long offset = 0;
            // LocalName-match để không phụ thuộc vào namespace
            // ("http://schemas.microsoft.com/win/2004/08/events/event") — fixture
            // hand-written có thể vô tình bỏ namespace.
            foreach (var ev in doc.Descendants().Where(e => e.Name.LocalName == "Event"))
            {
                ct.ThrowIfCancellationRequested();
                offset++;
                var rec = ReadOneEvent(ev, file, offset);
                if (rec is not null) { records.Add(rec); }
            }
        }, ct).ConfigureAwait(false);

        foreach (var r in records)
        {
            yield return r;
        }
    }

    /// <summary>
    /// Đọc một element &lt;Event&gt;. Parse &lt;System&gt; để lấy ProviderName /
    /// EventID / TimeCreated / Computer, và &lt;EventData&gt; để trích các cặp
    /// &lt;Data Name="X"&gt;Y&lt;/Data&gt;.
    /// </summary>
    private static LogRecord? ReadOneEvent(XElement ev, RawLogFile file, long offset)
    {
        string providerName = string.Empty;
        int eventId = 0;
        DateTimeOffset? timestamp = null;
        string computer = string.Empty;
        byte? level = null;
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var child in ev.Descendants())
        {
            switch (child.Name.LocalName)
            {
                case "Provider":
                    providerName = (string?)child.Attribute("Name") ?? string.Empty;
                    break;

                case "EventID":
                    if (int.TryParse(child.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id))
                    {
                        eventId = id;
                    }
                    break;

                case "Level":
                    if (byte.TryParse(child.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var lvl))
                    {
                        level = lvl;
                    }
                    break;

                case "TimeCreated":
                    var systemTime = (string?)child.Attribute("SystemTime");
                    if (!string.IsNullOrEmpty(systemTime) &&
                        DateTimeOffset.TryParse(systemTime, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var ts))
                    {
                        timestamp = ts;
                    }
                    break;

                case "Computer":
                    computer = child.Value;
                    break;

                case "Data":
                    // <EventData>/<Data Name="X">Y</Data>
                    var dataName = (string?)child.Attribute("Name");
                    if (!string.IsNullOrEmpty(dataName))
                    {
                        fields[dataName] = child.Value;
                    }
                    break;

                default:
                    // Các wrapper element khác (System, EventData, UserData…) — descent
                    // đã bao quát con của chúng nên không cần action riêng ở đây.
                    break;
            }
        }

        // Dispatch ID theo provider — y hệt WindowsEvtxParser.
        string? kind;
        if (providerName.StartsWith(SysmonProviderPrefix, StringComparison.OrdinalIgnoreCase))
        {
            if (!SysmonIdToKind.TryGetValue(eventId, out kind)) { return null; }
        }
        else
        {
            if (!IdToKind.TryGetValue(eventId, out kind)) { return null; }
        }

        fields["EventId"] = eventId.ToString(CultureInfo.InvariantCulture);
        fields["Provider"] = providerName;
        if (!string.IsNullOrEmpty(computer)) { fields["MachineName"] = computer; }

        return new LogRecord
        {
            Timestamp = timestamp ?? DateTimeOffset.UtcNow,
            SourceFile = file.OriginalPath,
            SourceOffset = offset,
            Os = "windows",
            RawLine = $"EventID={eventId} Provider={providerName}",
            EventKind = kind,
            Fields = fields,
            NativeLevel = level
        };
    }
}
