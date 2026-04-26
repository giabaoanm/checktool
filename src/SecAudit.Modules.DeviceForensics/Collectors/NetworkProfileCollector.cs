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
///     — friendly name, category (Public/Private/Domain), NameType (wireless / wired /
///     mobile / VPN), DateCreated, DateLastConnected. Both date values are SYSTEMTIME
///     blobs (16-byte little-endian).
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
        return results
            .OrderBy(w => w.ProfileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
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
