using System.Net;

namespace SecAudit.Modules.LanScanner.Models;

/// <summary>
/// A local IPv4 subnet detected from a live adapter.
/// </summary>
public sealed record SubnetInfo(
    string InterfaceName,
    IPAddress LocalAddress,
    IPAddress NetworkAddress,
    int PrefixLength,
    int HostCount);

/// <summary>
/// Result of host discovery on a subnet — one row per responsive host.
/// </summary>
public sealed record DiscoveredHost(
    IPAddress Address,
    string? MacAddress,
    bool RespondedToPing,
    bool RespondedToArp);

/// <summary>
/// Result of a TCP connect probe on a single (host, port).
/// </summary>
public sealed record OpenPort(
    IPAddress Host,
    int Port,
    string? Banner);
