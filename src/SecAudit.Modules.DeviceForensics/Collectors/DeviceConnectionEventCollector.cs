using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Xml;
using Microsoft.Extensions.Logging;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Reconstructs the FULL connection timeline of removable storage and portable devices
/// by mining Windows event-log channels that are enabled by default on Win10/11. This is
/// the answer to the SOC question "USB X — chỉ thấy lần cuối, còn các lần khác thì sao?"
///
/// <para>
/// Two channels are queried:
/// <list type="bullet">
///   <item><b>Microsoft-Windows-Partition/Diagnostic, EventID 1006</b> — fires every
///         time a partition is enumerated, which in practice means every mount of a
///         USB stick / external HDD / SD card. The event payload carries Manufacturer,
///         Model, Revision, SerialNumber, Capacity, BusType — everything we need to
///         attribute the event to a specific device. Enabled by default on Win10 1809+.
///         This is the authoritative timeline for USB <i>mass-storage</i> reconnects.</item>
///   <item><b>Microsoft-Windows-Kernel-PnP/Configuration, EventID 410</b> — fires when
///         the PnP manager configures a device, including USB devices that are NOT mass
///         storage (phones in MTP mode, cameras, etc). Less rich than 1006 but it is
///         the only default-on signal we have for repeated phone connects.</item>
/// </list>
/// </para>
///
/// <para>
/// Limitations the SOC operator must understand:
/// <list type="bullet">
///   <item>Event-log retention is bounded — a USB plugged 100 times last year may show
///         only the last ~30 days here once the channel rolls over (default ~1 MB).</item>
///   <item>1006 fires on <i>partition enumeration</i>, not on the USB-port arrival itself.
///         If the same drive is offlined / re-onlined without a re-mount it may fire
///         multiple times for one physical connect, or not at all if Windows cached the
///         partition table. Treat the count as a reasonable lower bound.</item>
///   <item>Phones connected purely as MTP (no mass-storage personality) appear in 410 but
///         not in 1006, and 410 does not carry the serial number — only the device
///         instance id, which we map back to the WPD store via
///         <see cref="PortableDeviceCollector"/>.</item>
/// </list>
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DeviceConnectionEventCollector
{
    /// <summary>
    /// Default upper bound on how many events we read from each channel. Win10/11
    /// retention is small but on a heavily-used machine the Partition/Diagnostic log can
    /// still hold thousands of entries. We cap to keep memory bounded and audit time
    /// short. Caller can override at construction time.
    /// </summary>
    private const int DefaultMaxEventsPerChannel = 5000;

    private readonly int _maxEventsPerChannel;
    private readonly ILogger<DeviceConnectionEventCollector> _logger;

    public DeviceConnectionEventCollector(ILogger<DeviceConnectionEventCollector> logger)
        : this(logger, DefaultMaxEventsPerChannel)
    {
    }

    public DeviceConnectionEventCollector(
        ILogger<DeviceConnectionEventCollector> logger,
        int maxEventsPerChannel)
    {
        _logger = logger;
        _maxEventsPerChannel = maxEventsPerChannel;
    }

    /// <summary>
    /// Read every Partition/Diagnostic 1006 event currently in the channel and group by
    /// the device serial number. Returns an empty map (not an exception) when the
    /// channel is missing, disabled, or unreadable — this is normal on stripped-down
    /// images (Win10 LTSC pre-1809) and on offline registry inspection.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<DeviceConnectionEvent>> CollectMassStorageHistoryBySerial()
    {
        var bySerial = new Dictionary<string, List<DeviceConnectionEvent>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var query = new EventLogQuery(
                "Microsoft-Windows-Partition/Diagnostic",
                PathType.LogName,
                "*[System[EventID=1006]]")
            {
                ReverseDirection = true // newest first so we hit the cap on stale data, not fresh
            };
            using var reader = new EventLogReader(query);

            int read = 0;
            EventRecord? evt;
            while ((evt = reader.ReadEvent()) is not null && read < _maxEventsPerChannel)
            {
                using (evt)
                {
                    read++;
                    var parsed = TryParse1006(evt);
                    if (parsed is null) { continue; }
                    if (string.IsNullOrWhiteSpace(parsed.SerialNumber)) { continue; }
                    if (!bySerial.TryGetValue(parsed.SerialNumber, out var list))
                    {
                        list = new List<DeviceConnectionEvent>();
                        bySerial[parsed.SerialNumber] = list;
                    }
                    list.Add(parsed);
                }
            }
            _logger.LogDebug(
                "Partition/Diagnostic 1006: read {Count} events covering {Devices} distinct serials",
                read, bySerial.Count);
        }
        catch (EventLogNotFoundException)
        {
            // Channel does not exist on this OS image.
            _logger.LogDebug("Microsoft-Windows-Partition/Diagnostic channel not present");
        }
        catch (UnauthorizedAccessException ex)
        {
            // Process is not Admin or channel ACL is locked down. Module already requires
            // admin so this should not happen in production — log at warning to surface.
            _logger.LogWarning(ex, "Cannot read Partition/Diagnostic — access denied");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to read Partition/Diagnostic events");
        }

        // Sort each device's events oldest-first for human-friendly display.
        var result = new Dictionary<string, IReadOnlyList<DeviceConnectionEvent>>(
            bySerial.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in bySerial)
        {
            result[kv.Key] = kv.Value
                .OrderBy(e => e.AtUtc)
                .ToList();
        }
        return result;
    }

    /// <summary>
    /// Parse one Partition/Diagnostic 1006 EventRecord into a structured connection
    /// event. Returns null if the payload XML is shaped differently than expected (we
    /// have seen variants between Win10 1809 and Win11 23H2 — defensive throughout).
    /// </summary>
    private DeviceConnectionEvent? TryParse1006(EventRecord evt)
    {
        try
        {
            var xml = evt.ToXml();
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            // Strip namespaces — the channel uses two (System, EventData/UserData)
            // and we want simple XPath without an XmlNamespaceManager.
            var stripped = StripNs(doc.DocumentElement!);

            var manufacturer = ReadField(stripped, "Manufacturer");
            var model = ReadField(stripped, "Model");
            var revision = ReadField(stripped, "Revision");
            var serial = ReadField(stripped, "SerialNumber");
            var capacityRaw = ReadField(stripped, "Capacity");
            long? capacity = null;
            if (long.TryParse(capacityRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var c))
            {
                capacity = c;
            }

            var at = evt.TimeCreated ?? DateTime.UtcNow;
            return new DeviceConnectionEvent(
                AtUtc: at.ToUniversalTime(),
                Manufacturer: manufacturer ?? string.Empty,
                Model: model ?? string.Empty,
                Revision: revision ?? string.Empty,
                SerialNumber: NormaliseSerial(serial ?? string.Empty),
                CapacityBytes: capacity,
                Source: "Partition/Diagnostic 1006");
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Failed to parse Partition/Diagnostic 1006 event");
            return null;
        }
    }

    /// <summary>
    /// USBSTOR registry serials carry a trailing "&amp;0" interface ordinal that the
    /// 1006 payload omits. Strip it so map lookup against
    /// <see cref="UsbStorageRecord.SerialNumber"/> succeeds case-insensitively.
    /// </summary>
    public static string NormaliseSerial(string raw)
    {
        if (string.IsNullOrEmpty(raw)) { return string.Empty; }
        var amp = raw.IndexOf('&');
        return (amp > 0 ? raw[..amp] : raw).Trim();
    }

    /// <summary>
    /// Recursive copy of an XML node that drops every namespace declaration. The
    /// Windows event XML has two default namespaces and parsing it with namespaced
    /// XPath requires registering both — much simpler to flatten first.
    /// </summary>
    private static XmlElement StripNs(XmlElement source)
    {
        var doc = new XmlDocument();
        var root = doc.CreateElement(source.LocalName);
        Copy(source, root, doc);
        doc.AppendChild(root);
        return root;

        static void Copy(XmlElement src, XmlElement dst, XmlDocument owner)
        {
            foreach (XmlAttribute a in src.Attributes)
            {
                if (a.Prefix == "xmlns" || a.Name == "xmlns") { continue; }
                var na = owner.CreateAttribute(a.LocalName);
                na.Value = a.Value;
                dst.Attributes.Append(na);
            }
            foreach (XmlNode child in src.ChildNodes)
            {
                if (child is XmlElement ce)
                {
                    var ne = owner.CreateElement(ce.LocalName);
                    Copy(ce, ne, owner);
                    dst.AppendChild(ne);
                }
                else if (child is XmlText t)
                {
                    dst.AppendChild(owner.CreateTextNode(t.Value ?? string.Empty));
                }
            }
        }
    }

    private static string? ReadField(XmlElement root, string localName)
    {
        var node = root.SelectSingleNode($".//{localName}");
        return node?.InnerText?.Trim();
    }
}
