using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Stateful rule that ingests <see cref="LogRecord"/> stream and emits <see cref="Finding"/>s.
/// Rules are fed records in timestamp order; they accumulate state (e.g. failed-logon
/// counter per user/IP) and flush findings when a threshold is crossed or at the end.
///
/// Each rule should be lightweight &amp; allocation-conscious because a single run may
/// process millions of records.
/// </summary>
public interface IDetectionRule
{
    string Id { get; }
    string Name { get; }

    /// <summary>Feed one record. Rule decides whether to emit a finding now.</summary>
    void Observe(LogRecord record, ForensicsContext ctx);

    /// <summary>Called once at end-of-stream to flush any accumulated state.</summary>
    void Flush(ForensicsContext ctx);

    /// <summary>
    /// Clear all accumulated state (counters, seen-sets, already-emitted sets).
    /// The engine calls this at the START of every <c>RunAsync</c> so that rule
    /// instances registered as DI singletons don't suppress findings on the
    /// second and subsequent runs. Default = no-op for stateless rules.
    /// </summary>
    void Reset() { }
}

/// <summary>
/// Shared state passed to every rule so they can publish findings, consult the user-provided
/// baseline (whitelist users / internal CIDRs), and write extracted evidence excerpts to the
/// chain-of-custody archive without depending on the engine directly.
/// </summary>
public sealed class ForensicsContext
{
    public required HashSet<string> UserWhitelist { get; init; }
    public required IReadOnlyList<CidrRange> InternalCidrs { get; init; }
    public required string MachineName { get; init; }

    private readonly List<Finding> _findings = new();
    public IReadOnlyList<Finding> Findings => _findings;

    public void Emit(Finding f) => _findings.Add(f);

    public bool IsInternalIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) { return true; } // empty = local session
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) { return false; }
        foreach (var c in InternalCidrs)
        {
            if (c.Contains(addr)) { return true; }
        }
        return false;
    }

    public bool IsWhitelistedUser(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) { return false; }
        return UserWhitelist.Count == 0 || UserWhitelist.Contains(user.Trim().ToLowerInvariant());
    }
}

/// <summary>Cheap CIDR container; no external dependency.</summary>
public sealed class CidrRange
{
    private readonly byte[] _network;
    private readonly int _prefix;

    public CidrRange(System.Net.IPAddress network, int prefix)
    {
        _network = network.GetAddressBytes();
        _prefix = prefix;
    }

    public static bool TryParse(string text, out CidrRange? range)
    {
        range = null;
        if (string.IsNullOrWhiteSpace(text)) { return false; }
        var slash = text.IndexOf('/');
        string ipPart = slash < 0 ? text.Trim() : text[..slash].Trim();
        if (!System.Net.IPAddress.TryParse(ipPart, out var ip)) { return false; }
        int defaultPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        int prefix = defaultPrefix;
        if (slash >= 0 && !int.TryParse(text[(slash + 1)..].Trim(), out prefix)) { return false; }
        if (prefix < 0 || prefix > defaultPrefix) { return false; }
        range = new CidrRange(ip, prefix);
        return true;
    }

    public bool Contains(System.Net.IPAddress addr)
    {
        var bytes = addr.GetAddressBytes();
        if (bytes.Length != _network.Length) { return false; }
        int full = _prefix / 8;
        int rem = _prefix % 8;
        for (int i = 0; i < full; i++)
        {
            if (bytes[i] != _network[i]) { return false; }
        }
        if (rem == 0) { return true; }
        int mask = 0xFF << (8 - rem) & 0xFF;
        return (bytes[full] & mask) == (_network[full] & mask);
    }
}
