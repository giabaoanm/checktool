using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Reads the persisted IPv4 config of every network adapter from
/// <c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{adapterGuid}</c>
/// and joins it with the friendly connection name from
/// <c>HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-...}\{adapterGuid}\Connection\Name</c>.
///
/// <para>
/// The compliance signal we surface for the SOC operator: the deployment policy at Công an
/// tỉnh Sơn La requires every workstation to use a fixed static IP issued by the network
/// administrator. Adapters that pick up an address from DHCP (<see cref="InterfaceIpRecord.IsStatic"/>
/// = <c>false</c>) violate the policy. Static adapters whose <c>ConfigChangedUtc</c> bumped
/// recently are also flagged because that means the IP plan was changed without going
/// through the normal change-management process.
/// </para>
///
/// <para>
/// Distinguishing static from DHCP:
/// <list type="bullet">
///   <item><c>EnableDHCP=1</c> + populated <c>DhcpIPAddress</c> ⇒ DHCP-leased.</item>
///   <item><c>EnableDHCP=0</c> + non-empty <c>IPAddress</c> not equal to "0.0.0.0" ⇒ Static.</item>
///   <item>Anything else (no IP at all) ⇒ disconnected/disabled, not flagged.</item>
/// </list>
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpConfigCollector
{
    private const string TcpipInterfacesKey =
        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    private const string NetworkAdaptersKey =
        @"SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}";

    private readonly IRegistryReader _registry;
    private readonly ILogger<IpConfigCollector> _logger;

    public IpConfigCollector(IRegistryReader registry, ILogger<IpConfigCollector> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    public IReadOnlyList<InterfaceIpRecord> Collect()
    {
        var results = new List<InterfaceIpRecord>();
        IReadOnlyList<string> adapterGuids;
        try
        {
            adapterGuids = _registry.GetSubKeyNames(RegistryHive.LocalMachine, TcpipInterfacesKey);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cannot enumerate Tcpip\\Parameters\\Interfaces");
            return results;
        }

        foreach (var guid in adapterGuids)
        {
            // Only "{guid}" subkeys are real adapters; Tcpip also stores per-tunnel GUIDs
            // but those still match the brace pattern.
            if (!guid.StartsWith('{'))
            {
                continue;
            }

            var keyPath = $@"{TcpipInterfacesKey}\{guid}";
            var enableDhcp = (_registry.GetValue(RegistryHive.LocalMachine, keyPath, "EnableDHCP") as int?) ?? 1;

            var staticIp = FirstNonEmpty(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "IPAddress"));
            var staticGw = FirstNonEmpty(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "DefaultGateway"));
            var dhcpIp = NormaliseIp(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "DhcpIPAddress") as string);
            var dhcpServer = NormaliseIp(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "DhcpServer") as string);
            var lease = ParseUnixLease(_registry.GetValue(RegistryHive.LocalMachine, keyPath, "LeaseObtainedTime"));

            // No IP plane at all — adapter probably never came up, skip silently.
            if (staticIp is null && dhcpIp is null)
            {
                continue;
            }

            var isStatic = enableDhcp == 0 && staticIp is not null;
            var friendly = TryReadFriendlyName(guid);
            // LastWriteTime of the Tcpip\Parameters\Interfaces\{guid} key is the most
            // accurate "lần cuối thay đổi cấu hình IP" we can get without auditing
            // enabled. NB: on DHCP adapters this also bumps on every lease renewal, so the
            // signal is most meaningful when IsStatic == true.
            var configChanged = _registry.GetLastWriteTime(RegistryHive.LocalMachine, keyPath);

            results.Add(new InterfaceIpRecord(
                AdapterGuid: guid,
                FriendlyName: friendly,
                IsStatic: isStatic,
                StaticIpv4: isStatic ? staticIp : null,
                StaticGatewayIpv4: isStatic ? staticGw : null,
                DhcpIpAddress: isStatic ? null : dhcpIp,
                DhcpServer: isStatic ? null : dhcpServer,
                DhcpLeaseObtainedUtc: isStatic ? null : lease,
                ConfigChangedUtc: configChanged));
        }

        return results
            .OrderByDescending(r => r.IsStatic)
            .ThenBy(r => r.FriendlyName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private string? TryReadFriendlyName(string adapterGuid)
    {
        try
        {
            return _registry.GetValue(
                RegistryHive.LocalMachine,
                $@"{NetworkAdaptersKey}\{adapterGuid}\Connection",
                "Name") as string;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Friendly name lookup failed for {Guid}", adapterGuid);
            return null;
        }
    }

    /// <summary>
    /// IPAddress / DefaultGateway are REG_MULTI_SZ. Empty string entries and "0.0.0.0"
    /// stubs are filtered out — Windows persists those as the "no static IP" sentinel.
    /// </summary>
    private static string? FirstNonEmpty(object? raw)
    {
        if (raw is string[] arr)
        {
            foreach (var s in arr)
            {
                var v = NormaliseIp(s);
                if (v is not null) { return v; }
            }
            return null;
        }
        if (raw is string single)
        {
            return NormaliseIp(single);
        }
        return null;
    }

    private static string? NormaliseIp(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) { return null; }
        var trimmed = s.Trim();
        if (trimmed == "0.0.0.0") { return null; }
        return trimmed;
    }

    /// <summary>
    /// LeaseObtainedTime is REG_DWORD seconds since the Unix epoch (UTC) — a Windows
    /// quirk dating back to the original BSD-derived dhcpcsvc implementation.
    /// </summary>
    private static DateTime? ParseUnixLease(object? raw)
    {
        if (raw is int seconds && seconds > 0)
        {
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime;
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }
        return null;
    }

    // Kept here even though not currently called — useful when we add ipv6 / lease-end
    // formatting in a later iteration.
    private static string FormatTime(DateTime t) =>
        t.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
}
