using System.Net.NetworkInformation;
using System.Net.Sockets;
using SecAudit.Reporting.Models;

namespace SecAudit.Reporting.Services;

/// <summary>
/// Enumerates active IPv4 interfaces and produces <see cref="NetworkAddress"/> rows
/// for the device-profile section of the report. Skips loopback and tunnel adapters.
/// </summary>
public static class NetworkAddressCollector
{
    public static IReadOnlyList<NetworkAddress> Collect()
    {
        var result = new List<NetworkAddress>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var props = nic.GetIPProperties();
            string? ipv4 = null;
            string? ipv6 = null;
            foreach (var addr in props.UnicastAddresses)
            {
                if (addr.Address.AddressFamily == AddressFamily.InterNetwork && ipv4 is null)
                {
                    ipv4 = addr.Address.ToString();
                }
                else if (addr.Address.AddressFamily == AddressFamily.InterNetworkV6
                    && ipv6 is null
                    && !addr.Address.IsIPv6LinkLocal)
                {
                    ipv6 = addr.Address.ToString();
                }
            }
            if (ipv4 is null && ipv6 is null)
            {
                continue;
            }

            // Format MAC as AA:BB:CC:DD:EE:FF for readability in the report.
            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            var mac = macBytes.Length == 0 ? "(unknown)" : string.Join(":", macBytes.Select(b => b.ToString("X2")));

            result.Add(new NetworkAddress(
                InterfaceName: nic.Name,
                MacAddress: mac,
                IPv4: ipv4 ?? "(none)",
                IPv6: ipv6));
        }
        return result;
    }
}
