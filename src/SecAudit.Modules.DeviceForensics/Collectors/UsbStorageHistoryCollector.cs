using System.Globalization;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Enumerates every USB mass-storage device that has ever been mounted on this machine
/// from <c>HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR</c>, then enriches each record with
/// the precise lifecycle timestamps:
///
/// <list type="bullet">
///   <item>FirstInstall / LastArrival / LastRemoval — read directly from the device's
///         DEVPKEY properties (<see cref="DevPropertyReader"/>). These are the actual
///         per-device "last connected at" / "last unplugged at" datapoints maintained by
///         the PnP manager.</item>
///   <item>InstallEventCount — number of <c>Device Install</c> blocks for this device in
///         <c>C:\Windows\inf\setupapi.dev.log</c>. Counts driver installs/reinstalls
///         (not individual plug-in events). A USB stick plugged 50 times typically shows
///         InstallEventCount=1.</item>
/// </list>
///
/// <para>
/// Why USBSTOR (and not the broader <c>Enum\USB</c>): USBSTOR contains <i>only</i>
/// removable storage class devices (USB sticks, USB-attached HDDs, SD card readers).
/// Phones and cameras land under <c>Enum\USB</c> with <c>WPD/MTP</c> sub-trees and are
/// handled by <see cref="PortableDeviceCollector"/>.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UsbStorageHistoryCollector
{
    private const string UsbStorRoot = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";
    private const string SetupApiLogPath = @"C:\Windows\inf\setupapi.dev.log";
    private static readonly string[] UsbStorPrefixOnly = { "USBSTOR\\" };

    private readonly IRegistryReader _registry;
    private readonly DevPropertyReader _devProps;
    private readonly ILogger<UsbStorageHistoryCollector> _logger;

    public UsbStorageHistoryCollector(
        IRegistryReader registry,
        DevPropertyReader devProps,
        ILogger<UsbStorageHistoryCollector> logger)
    {
        _registry = registry;
        _devProps = devProps;
        _logger = logger;
    }

    public IReadOnlyList<UsbStorageRecord> Collect()
    {
        var results = new List<UsbStorageRecord>();
        var installCounts = ParseSetupApiInstallCounts(UsbStorPrefixOnly);

        IReadOnlyList<string> vidPids;
        try
        {
            vidPids = _registry.GetSubKeyNames(RegistryHive.LocalMachine, UsbStorRoot);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cannot enumerate USBSTOR root");
            return results;
        }

        foreach (var vidPid in vidPids)
        {
            var (vendor, product, revision) = ParseVidPid(vidPid);
            IReadOnlyList<string> serials;
            try
            {
                serials = _registry.GetSubKeyNames(
                    RegistryHive.LocalMachine, $@"{UsbStorRoot}\{vidPid}");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Cannot enumerate USBSTOR\\{VidPid}", vidPid);
                continue;
            }

            foreach (var serial in serials)
            {
                var deviceKey = $@"{UsbStorRoot}\{vidPid}\{serial}";
                var friendly = _registry.GetValue(
                    RegistryHive.LocalMachine, deviceKey, "FriendlyName") as string;
                var instanceId = $@"USBSTOR\{vidPid}\{serial}";

                // DEVPKEY date properties — best-quality source for connection times.
                // Wrap defensively: even with the SafeGet inside DevPropertyReader, a
                // pathological device entry (e.g. orphaned on an offline hive) shouldn't
                // be allowed to kill the whole enumeration. Approximate "last seen" with
                // the device key's LastWriteTime when DEVPKEY is unreadable.
                DateTime? firstInstall = null, lastArrival = null, lastRemoval = null;
                try
                {
                    (firstInstall, lastArrival, lastRemoval) = _devProps.ReadDeviceLifecycle(deviceKey);
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "DEVPKEY lookup failed for {Device}", deviceKey);
                }
                if (lastArrival is null)
                {
                    lastArrival = _registry.GetLastWriteTime(RegistryHive.LocalMachine, deviceKey);
                }

                // Cross-reference setupapi log for install-event count. Use the FULL instance
                // id (with trailing "&0") as the key — that is what setupapi writes.
                var lookupKey = NormaliseInstanceKey(instanceId);
                installCounts.TryGetValue(lookupKey, out var installCount);

                results.Add(new UsbStorageRecord(
                    Vendor: vendor,
                    Product: product,
                    Revision: revision,
                    SerialNumber: serial,
                    FriendlyName: friendly,
                    FirstInstallUtc: firstInstall,
                    LastArrivalUtc: lastArrival,
                    LastRemovalUtc: lastRemoval,
                    InstallEventCount: installCount,
                    DeviceInstanceId: instanceId));
            }
        }

        return results
            .OrderByDescending(r => r.LastArrivalUtc ?? r.FirstInstallUtc ?? DateTime.MinValue)
            .ToList();
    }

    /// <summary>Decodes <c>Disk&amp;Ven_Kingston&amp;Prod_DataTraveler&amp;Rev_PMAP</c>.</summary>
    private static (string Vendor, string Product, string Revision) ParseVidPid(string raw)
    {
        var v = ExtractToken(raw, "Ven_");
        var p = ExtractToken(raw, "Prod_");
        var r = ExtractToken(raw, "Rev_");
        return (Decode(v), Decode(p), Decode(r));
    }

    private static string ExtractToken(string raw, string prefix)
    {
        var idx = raw.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) { return string.Empty; }
        var rest = raw.AsSpan(idx + prefix.Length);
        var amp = rest.IndexOf('&');
        return amp < 0 ? rest.ToString() : rest[..amp].ToString();
    }

    /// <summary>Vendor/Product strings are "_" -separated; humanise for display.</summary>
    private static string Decode(string token) => token.Replace('_', ' ').Trim();

    /// <summary>
    /// Lower-cases the instance id for case-insensitive map lookup against the setupapi
    /// install-event index. Both sides keep the trailing interface ordinal (e.g. "&amp;0")
    /// so registry and log entries align byte-for-byte.
    /// </summary>
    internal static string NormaliseInstanceKey(string instanceId)
        => instanceId.ToLowerInvariant();

    /// <summary>
    /// Single-pass scan of setupapi.dev.log. Counts how many <c>Device Install</c> blocks
    /// reference each device instance id (lower-cased) whose prefix is in
    /// <paramref name="prefixesAccepted"/>. Public so <see cref="PortableDeviceCollector"/>
    /// can reuse the same parser for <c>USB\\VID_</c> and <c>SWD\\WPDBUSENUM</c> blocks.
    /// </summary>
    public Dictionary<string, int> ParseSetupApiInstallCounts(IReadOnlyList<string> prefixesAccepted)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(SetupApiLogPath))
        {
            return map;
        }
        try
        {
            using var stream = new FileStream(
                SetupApiLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (!line.Contains("Device Install", StringComparison.Ordinal))
                {
                    continue;
                }
                var instance = ExtractInstance(line, prefixesAccepted);
                if (instance is null)
                {
                    continue;
                }
                var key = instance.ToLowerInvariant();
                map[key] = map.TryGetValue(key, out var c) ? c + 1 : 1;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to parse {Path}", SetupApiLogPath);
        }
        return map;
    }

    /// <summary>Extracts the instance id between <c>"- "</c> and <c>"]"</c> on a Device-Install line.</summary>
    private static string? ExtractInstance(string line, IReadOnlyList<string> prefixesAccepted)
    {
        // Format: ">>>  [Device Install (Hardware initiated) - <INSTANCE_ID>]"
        var openBracket = line.IndexOf('[');
        if (openBracket < 0) { return null; }
        var dashSpace = line.IndexOf(" - ", openBracket, StringComparison.Ordinal);
        if (dashSpace < 0) { return null; }
        var closeBracket = line.IndexOf(']', dashSpace);
        if (closeBracket < 0) { return null; }
        var instance = line.Substring(dashSpace + 3, closeBracket - dashSpace - 3).Trim();
        foreach (var prefix in prefixesAccepted)
        {
            if (instance.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return instance;
            }
        }
        return null;
    }
}
