using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Modules.LanScanner.Models;

namespace SecAudit.Modules.LanScanner.Discovery;

/// <summary>
/// Two-pronged host sweep:
///  * ICMP echo with short timeout (fails silently when firewalls drop ICMP).
///  * ARP via iphlpapi.SendARP (pure Win32, no Npcap needed) — detects hosts that
///    block ICMP but still respond to link-layer ARP within the same subnet.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostDiscovery
{
    private readonly ILogger<HostDiscovery> _logger;

    public HostDiscovery(ILogger<HostDiscovery> logger) => _logger = logger;

    public async Task<IReadOnlyList<DiscoveredHost>> SweepAsync(
        SubnetInfo subnet,
        IProgress<(int done, int total)>? progress,
        CancellationToken ct)
    {
        var hosts = SubnetDiscovery.EnumerateHosts(subnet).ToArray();
        var results = new ConcurrentDictionary<IPAddress, DiscoveredHost>();
        int done = 0;

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = ct,
            MaxDegreeOfParallelism = 64
        };

        await Parallel.ForEachAsync(hosts, parallelOptions, async (ip, token) =>
        {
            bool pinged = await TryPingAsync(ip, token).ConfigureAwait(false);
            var (arpOk, mac) = TryArp(ip);

            if (pinged || arpOk)
            {
                results[ip] = new DiscoveredHost(ip, mac, pinged, arpOk);
            }
            var current = Interlocked.Increment(ref done);
            progress?.Report((current, hosts.Length));
        }).ConfigureAwait(false);

        _logger.LogInformation("Subnet {Net}/{Prefix}: {Alive}/{Total} alive",
            subnet.NetworkAddress, subnet.PrefixLength, results.Count, hosts.Length);
        return results.Values
            .OrderBy(h => IpToUInt(h.Address))
            .ToArray();
    }

    private static async Task<bool> TryPingAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, 400).WaitAsync(ct).ConfigureAwait(false);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }

    private (bool ok, string? mac) TryArp(IPAddress ip)
    {
        try
        {
            var macBuf = new byte[6];
            int bufLen = macBuf.Length;
#pragma warning disable CS0618 // IPAddress.Address is obsolete but SendARP requires the 32-bit form
            uint dest = (uint)ip.Address;
#pragma warning restore CS0618
            int rc = SendARP(dest, 0, macBuf, ref bufLen);
            if (rc == 0 && bufLen == 6)
            {
                var mac = string.Join(":", macBuf.Select(b => b.ToString("X2")));
                if (mac == "00:00:00:00:00:00")
                {
                    return (false, null);
                }
                return (true, mac);
            }
            return (false, null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SendARP failed for {Ip}", ip);
            return (false, null);
        }
    }

    private static uint IpToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLen);
}
