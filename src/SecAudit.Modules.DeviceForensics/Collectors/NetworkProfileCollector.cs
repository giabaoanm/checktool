using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Reads the persistent NetworkList registry — every network profile this machine has
/// ever joined survives here, even after the network is "forgotten" via Settings UI.
/// This is gold for IR: it tells you "this air-gapped workstation was on a public WiFi
/// last Tuesday".
///
/// <para>
/// Two stores get joined:
/// <list type="bullet">
///   <item>
///     <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{guid}</c>
    ///     — friendly name, category (Public/Private/Domain), NameType registry hint,
    ///     DateCreated, DateLastConnected. Both date values are SYSTEMTIME blobs
    ///     (16-byte little-endian). NameType is kept as evidence only; remembered Wi-Fi is
    ///     determined from the Wlansvc XML store, not from this hint.
///   </item>
///   <item>
///     <c>...\NetworkList\Signatures\{Managed|Unmanaged}\{sig}</c> — DefaultGatewayMac
///     (the cleanest network identity — same gateway MAC across reconnects), Description
///     (often the SSID for WiFi), ProfileGuid (joins back to Profiles).
///   </item>
/// </list>
/// </para>
///
/// <para>
/// Wi-Fi profiles also have a separate cache under
/// <c>%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\{ifGuid}\{profileGuid}.xml</c>
/// — read by <see cref="CollectWifi"/>. We do NOT extract the plaintext key (that requires
/// DPAPI under SYSTEM, which is out of our scoped permissions and would land us in the
/// "credential audit" zone we permanently dropped); we report only profile name + auth /
/// encryption to demonstrate that an unauthorised WiFi was at some point remembered.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NetworkProfileCollector
{
    private const string ProfilesKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";
    private const string SignaturesUnmanagedKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged";
    private const string SignaturesManagedKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed";
    private const string WlanProfilesRoot =
        @"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces";

    private static readonly string[] VirtualPnpPrefixes =
    [
        "ROOT\\",
        "SWD\\",
        "VMS_",
        "VMS\\",
        "VMBUS\\",
        "BTH\\",
        "BTHENUM\\",
        "HTREE\\",
        "TAP\\",
        "TUN\\"
    ];

    private static readonly string[] VirtualNameMarkers =
    [
        "virtual",
        "wi-fi direct",
        "wifi direct",
        "wireless direct",
        "microsoft wi-fi direct",
        "microsoft wifi direct",
        "hosted network",
        "miracast",
        "softap",
        "soft ap",
        "hyper-v",
        "vmware",
        "virtualbox",
        "vbox",
        "tap-windows",
        "tap windows",
        "wintun",
        "wireguard",
        "openvpn",
        "vpn",
        "zerotier",
        "zero tier",
        "npcap",
        "loopback",
        "wan miniport",
        "bluetooth"
    ];

    private readonly IRegistryReader _registry;
    private readonly ILogger<NetworkProfileCollector> _logger;

    public NetworkProfileCollector(IRegistryReader registry, ILogger<NetworkProfileCollector> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    public IReadOnlyList<NetworkProfileRecord> CollectProfiles()
    {
        // Build profileGuid → (description, mac, source) lookup from the two Signature stores.
        var sigByProfile = new Dictionary<string, (string? Desc, string? Mac, string Source)>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, source) in new[]
                 {
                     (SignaturesUnmanagedKey, "Unmanaged"),
                     (SignaturesManagedKey, "Managed"),
                 })
        {
            IReadOnlyList<string> sigKeys;
            try { sigKeys = _registry.GetSubKeyNames(RegistryHive.LocalMachine, path); }
            catch (Exception ex) { _logger.LogDebug(ex, "Cannot enumerate {Path}", path); continue; }
            foreach (var sig in sigKeys)
            {
                var guid = _registry.GetValue(RegistryHive.LocalMachine, $@"{path}\{sig}", "ProfileGuid") as string;
                if (string.IsNullOrEmpty(guid))
                {
                    continue;
                }
                var desc = _registry.GetValue(RegistryHive.LocalMachine, $@"{path}\{sig}", "Description") as string;
                var mac = FormatMac(_registry.GetValue(RegistryHive.LocalMachine, $@"{path}\{sig}", "DefaultGatewayMac"));
                sigByProfile[guid] = (desc, mac, source);
            }
        }

        var profiles = new List<NetworkProfileRecord>();
        IReadOnlyList<string> profileGuids;
        try { profileGuids = _registry.GetSubKeyNames(RegistryHive.LocalMachine, ProfilesKey); }
        catch (Exception ex) { _logger.LogDebug(ex, "Cannot enumerate NetworkList\\Profiles"); return profiles; }

        foreach (var guid in profileGuids)
        {
            var keyPath = $@"{ProfilesKey}\{guid}";
            var name = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "ProfileName") as string ?? "(không tên)";
            var category = (_registry.GetValue(RegistryHive.LocalMachine, keyPath, "Category") as int?) ?? -1;
            var nameType = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "NameType") as int?;
            var firstConn = ParseSystemTime(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "DateCreated"));
            var lastConn = ParseSystemTime(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "DateLastConnected"));

            sigByProfile.TryGetValue(guid, out var sig);
            profiles.Add(new NetworkProfileRecord(
                ProfileGuid: guid,
                ProfileName: name,
                Category: category,
                Source: sig.Source ?? "Unknown",
                Description: sig.Desc,
                DefaultGatewayMac: sig.Mac,
                NameType: nameType,
                FirstConnectedUtc: firstConn,
                LastConnectedUtc: lastConn));
        }

        return profiles
            .OrderByDescending(p => p.LastConnectedUtc ?? DateTime.MinValue)
            .ToList();
    }

    public IReadOnlyList<WifiProfileRecord> CollectWifi()
    {
        var results = new List<WifiProfileRecord>();
        if (!Directory.Exists(WlanProfilesRoot))
        {
            return results;
        }
        IEnumerable<string> ifaceFolders;
        try
        {
            ifaceFolders = Directory.EnumerateDirectories(WlanProfilesRoot);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cannot enumerate Wlansvc Interfaces folder");
            return results;
        }
        foreach (var iface in ifaceFolders)
        {
            string[] xmlFiles;
            try { xmlFiles = Directory.GetFiles(iface, "*.xml"); }
            catch { continue; }
            foreach (var xml in xmlFiles)
            {
                try
                {
                    var content = File.ReadAllText(xml);
                    var name = ExtractTag(content, "name") ?? Path.GetFileNameWithoutExtension(xml);
                    // Filter out system-generated Wi-Fi Direct profiles. These are
                    // created automatically by Windows for Miracast / Wi-Fi Direct
                    // printers / BlueTooth tethering — NOT real networks the user
                    // joined. Operator at Sơn La saw "WFD_GROUP_OWNER_PROFILE" in the
                    // remembered-Wi-Fi list and reported it as wrong.
                    if (IsSystemGeneratedProfileName(name))
                    {
                        continue;
                    }
                    var auth = ExtractTag(content, "authentication") ?? "?";
                    var enc = ExtractTag(content, "encryption") ?? "?";
                    var mode = ExtractTag(content, "connectionMode") ?? "?";
                    results.Add(new WifiProfileRecord(name, auth, enc, mode));
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed parsing WLAN profile {File}", xml);
                }
            }
        }
        // Deduplicate: each WLAN interface keeps its own copy of every profile, so a
        // machine with N WiFi adapters reports each network N times. Operator at Sơn La
        // saw "2569" listed 5 times — once per interface that had previously connected
        // to it. Group by (Name + Auth) to keep distinct security configurations even
        // when names match (rare but possible: same SSID with different auth = open
        // hotspot vs WPA3 corporate spoof of same name).
        var deduped = results
            .GroupBy(w => $"{w.ProfileName}|{w.AuthMethod}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(w => w.ProfileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return deduped;
    }

    /// <summary>
    /// Enumerate every Wi-Fi adapter (built-in card OR USB dongle) that has EVER been
    /// registered on this machine. Source: each subfolder under
    /// <c>%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\</c> = one Wi-Fi adapter
    /// that stored at least one profile. The folder name is the interface GUID.
    ///
    /// <para>
    /// We match each GUID against currently-attached interfaces (via
    /// <c>NetworkInterface.GetAllNetworkInterfaces</c>) to recover friendly name +
    /// description. Adapters no longer attached (e.g. unplugged USB dongle) report
    /// FriendlyName=null — their GUID and per-adapter profile count are still useful
    /// forensic evidence ("an unauthorised Wi-Fi card was at some point installed").
    /// </para>
    /// </summary>
    /// <summary>
    /// Network adapter PnP class. Every legit Windows NIC (physical or virtual) lives
    /// under this class. The per-interface <c>Connection</c> sub-key carries the
    /// <c>Name</c> (friendly name from Network Connections panel) and
    /// <c>PnpInstanceID</c> (back-reference to the hardware device) — both are
    /// preserved even after the adapter is uninstalled, which is exactly what we need
    /// to identify stale {ifGuid} entries belonging to a removed Wi-Fi card.
    /// </summary>
    private const string NetworkClassKey =
        @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002bE10318}";

    public IReadOnlyList<WifiAdapterRecord> CollectWifiAdapters()
    {
        var results = new List<WifiAdapterRecord>();
        if (!Directory.Exists(WlanProfilesRoot)) { return results; }

        IEnumerable<string> ifaceFolders;
        try
        {
            ifaceFolders = Directory.EnumerateDirectories(WlanProfilesRoot);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cannot enumerate Wlansvc Interfaces folder");
            return results;
        }

        // Build a quick lookup of currently-attached Wi-Fi interfaces. Each NIC's Id
        // field is the same {guid} that Wlansvc uses for its folder name.
        Dictionary<string, System.Net.NetworkInformation.NetworkInterface> live;
        try
        {
            live = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)
                .ToDictionary(
                    n => NormaliseGuid(n.Id),
                    n => n,
                    StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "NetworkInterface.GetAllNetworkInterfaces failed");
            live = new Dictionary<string, System.Net.NetworkInformation.NetworkInterface>(StringComparer.OrdinalIgnoreCase);
        }

        foreach (var folder in ifaceFolders)
        {
            try
            {
                var folderName = Path.GetFileName(folder)?.Trim();
                if (string.IsNullOrWhiteSpace(folderName)) { continue; }
                var guid = NormaliseGuid(folderName);

                int profileCount = 0;
                try { profileCount = Directory.GetFiles(folder, "*.xml").Length; } catch { }

                DateTime? lastSeen = null;
                try { lastSeen = Directory.GetLastWriteTimeUtc(folder); } catch { }

                // Cross-reference with HKLM\SYSTEM\...\Network\{class}\{ifGuid}\Connection
                // to recover friendly name + PnpInstanceID even for adapters that have
                // since been uninstalled (NetworkInterface only sees currently-attached).
                var connKey = $@"{NetworkClassKey}\{guid}\Connection";
                string? regName = TryReadString(connKey, "Name");
                string? pnpId = TryReadString(connKey, "PnpInstanceID");
                string? regDesc = TryReadString(connKey, "Description");

                live.TryGetValue(guid, out var nic);
                var friendly = nic?.Name ?? regName;
                var description = nic?.Description
                                  ?? regDesc
                                  ?? (string.IsNullOrWhiteSpace(pnpId) ? null : pnpId);

                results.Add(new WifiAdapterRecord(
                    InterfaceGuid: guid,
                    FriendlyName: friendly,
                    Description: description,
                    PnpInstanceId: pnpId,
                    BusType: ClassifyBusType(pnpId, friendly, description),
                    IsCurrentlyAttached: nic is not null,
                    LastSeenUtc: lastSeen,
                    ProfilesStoredCount: profileCount));
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Failed reading Wi-Fi adapter folder {Folder}", folder);
            }
        }
        return results
            .OrderByDescending(a => a.IsCurrentlyAttached)
            .ThenByDescending(a => a.ProfilesStoredCount)
            .ToList();
    }

    /// <summary>
    /// Categorise a Wi-Fi adapter by PnP instance ID prefix and adapter labels.
    ///
    /// <para>
    /// Real physical adapters live under <c>PCI\</c> (built-in card), <c>USB\</c>
    /// (dongle), or <c>SDIO\</c>. Virtual/software adapters created by Windows
    /// Wi-Fi Direct, VPN clients, hypervisors, or packet-capture drivers often live
    /// under <c>SWD\</c>/<c>ROOT\</c> or only reveal themselves in the adapter name.
    /// Returns "Unknown" when there is not enough evidence to call the device physical
    /// or virtual.
    /// </para>
    /// </summary>
    internal static string ClassifyBusType(
        string? pnpInstanceId,
        string? friendlyName = null,
        string? description = null)
    {
        var pnp = pnpInstanceId?.TrimStart('{', '\\') ?? string.Empty;
        if (StartsWithAny(pnp, VirtualPnpPrefixes)
            || ContainsAny(friendlyName, VirtualNameMarkers)
            || ContainsAny(description, VirtualNameMarkers)
            || ContainsAny(pnpInstanceId, VirtualNameMarkers))
        {
            return "Virtual";
        }

        if (pnp.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase)
            || pnp.StartsWith("PCIE\\", StringComparison.OrdinalIgnoreCase))
        {
            return "PCI";
        }

        if (pnp.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase)
            || pnp.StartsWith("USBSTOR\\", StringComparison.OrdinalIgnoreCase))
        {
            return "USB";
        }

        if (pnp.StartsWith("SDIO\\", StringComparison.OrdinalIgnoreCase))
        {
            return "SDIO";
        }

        return "Unknown";
    }

    private static bool StartsWithAny(string? value, IEnumerable<string> prefixes)
    {
        if (string.IsNullOrWhiteSpace(value)) { return false; }
        foreach (var prefix in prefixes)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool ContainsAny(string? value, IEnumerable<string> markers)
    {
        if (string.IsNullOrWhiteSpace(value)) { return false; }
        foreach (var marker in markers)
        {
            if (value.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private string? TryReadString(string keyPath, string valueName)
    {
        try
        {
            return _registry.GetValue(RegistryHive.LocalMachine, keyPath, valueName) as string;
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Cannot read {Key}\\{Value}", keyPath, valueName);
            return null;
        }
    }

    /// <summary>Normalise GUID strings to lower-case "{xxxxxxxx-...}" form for stable lookup.</summary>
    internal static string NormaliseGuid(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) { return string.Empty; }
        var v = raw.Trim().ToLowerInvariant();
        if (!v.StartsWith('{')) { v = "{" + v; }
        if (!v.EndsWith('}')) { v += "}"; }
        return v;
    }

    /// <summary>
    /// True when <paramref name="name"/> is a profile auto-created by Windows for
    /// internal use (Wi-Fi Direct, Miracast, Internet Connection Sharing) and NOT a
    /// remembered network the user/admin chose to join.
    /// </summary>
    internal static bool IsSystemGeneratedProfileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) { return false; }
        var n = name.Trim();
        // WFD_GROUP_OWNER_PROFILE — Wi-Fi Direct (Miracast, printer, etc).
        if (n.StartsWith("WFD_", StringComparison.OrdinalIgnoreCase)) { return true; }
        // DIRECT-* — Wi-Fi Direct ad-hoc names (e.g. "DIRECT-xx-PRINTER").
        if (n.StartsWith("DIRECT-", StringComparison.OrdinalIgnoreCase)) { return true; }
        // Microsoft.MicrosoftWiFiDirect — sometimes appears as profile name.
        if (n.Contains("MicrosoftWiFiDirect", StringComparison.OrdinalIgnoreCase)) { return true; }
        return false;
    }

    /// <summary>Cheap XML scrape — avoids pulling System.Xml.Linq for two-line parses.</summary>
    private static string? ExtractTag(string xml, string tag)
    {
        // Match the FIRST occurrence of <tag>value</tag> (ignoring namespaces by accepting any prefix).
        var open = $"<{tag}>";
        var close = $"</{tag}>";
        var i = xml.IndexOf(open, StringComparison.OrdinalIgnoreCase);
        if (i < 0)
        {
            return null;
        }
        var start = i + open.Length;
        var end = xml.IndexOf(close, start, StringComparison.OrdinalIgnoreCase);
        if (end < 0)
        {
            return null;
        }
        return xml[start..end].Trim();
    }

    private static string? FormatMac(object? raw)
    {
        if (raw is byte[] bytes && bytes.Length == 6)
        {
            return string.Join(':', bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
        }
        return null;
    }

    /// <summary>
    /// SYSTEMTIME blob layout (16 bytes, little-endian):
    /// year(2) month(2) dayOfWeek(2) day(2) hour(2) minute(2) second(2) ms(2).
    /// Returns UTC.
    /// </summary>
    private static DateTime? ParseSystemTime(object? raw)
    {
        if (raw is not byte[] b || b.Length != 16)
        {
            return null;
        }
        try
        {
            var year = BitConverter.ToUInt16(b, 0);
            var month = BitConverter.ToUInt16(b, 2);
            // skip dayOfWeek at offset 4
            var day = BitConverter.ToUInt16(b, 6);
            var hour = BitConverter.ToUInt16(b, 8);
            var minute = BitConverter.ToUInt16(b, 10);
            var second = BitConverter.ToUInt16(b, 12);
            var ms = BitConverter.ToUInt16(b, 14);
            if (year < 1900 || month is 0 or > 12 || day is 0 or > 31)
            {
                return null;
            }
            return new DateTime(year, month, day, hour, minute, second, ms, DateTimeKind.Utc);
        }
        catch
        {
            return null;
        }
    }
}
