using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SecAudit.Modules.LanScanner.Models;

namespace SecAudit.Modules.LanScanner.Discovery;

/// <summary>
/// Enumerates local IPv4 adapters (skipping loopback / APIPA / link-local) and derives
/// the /24-or-larger subnet for each so the scanner knows which ranges to probe.
/// </summary>
public sealed class SubnetDiscovery
{
    private readonly ILogger<SubnetDiscovery> _logger;

    public SubnetDiscovery(ILogger<SubnetDiscovery> logger) => _logger = logger;

    public IReadOnlyList<SubnetInfo> Enumerate()
    {
        var results = new List<SubnetInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var props = nic.GetIPProperties();
            foreach (var addr in props.UnicastAddresses)
            {
                if (addr.Address.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }
                var ip = addr.Address;
                if (IPAddress.IsLoopback(ip))
                {
                    continue;
                }
                var octets = ip.GetAddressBytes();
                if (octets[0] == 169 && octets[1] == 254)
                {
                    continue; // APIPA
                }

                var prefix = addr.PrefixLength;
                if (prefix < 16 || prefix > 30)
                {
                    // Only scan reasonable small/medium LANs.
                    continue;
                }

                var network = GetNetworkAddress(ip, prefix);
                var hostCount = prefix >= 31 ? 0 : (1 << (32 - prefix)) - 2;
                results.Add(new SubnetInfo(
                    InterfaceName: nic.Name,
                    LocalAddress: ip,
                    NetworkAddress: network,
                    PrefixLength: prefix,
                    HostCount: hostCount));
            }
        }
        _logger.LogInformation("Found {Count} scannable subnet(s)", results.Count);
        return results;
    }

    public static IEnumerable<IPAddress> EnumerateHosts(SubnetInfo subnet)
    {
        var baseBytes = subnet.NetworkAddress.GetAddressBytes();
        uint baseInt = ((uint)baseBytes[0] << 24) | ((uint)baseBytes[1] << 16) |
                       ((uint)baseBytes[2] << 8) | baseBytes[3];
        uint count = subnet.PrefixLength >= 31 ? 0 : (1u << (32 - subnet.PrefixLength)) - 2;
        for (uint i = 1; i <= count; i++)
        {
            uint val = baseInt + i;
            yield return new IPAddress(new[]
            {
                (byte)((val >> 24) & 0xFF),
                (byte)((val >> 16) & 0xFF),
                (byte)((val >> 8) & 0xFF),
                (byte)(val & 0xFF)
            });
        }
    }

    private static IPAddress GetNetworkAddress(IPAddress ip, int prefix)
    {
        var bytes = ip.GetAddressBytes();
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        uint val = (((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) |
                    ((uint)bytes[2] << 8) | bytes[3]) & mask;
        return new IPAddress(new[]
        {
            (byte)((val >> 24) & 0xFF),
            (byte)((val >> 16) & 0xFF),
            (byte)((val >> 8) & 0xFF),
            (byte)(val & 0xFF)
        });
    }
}
