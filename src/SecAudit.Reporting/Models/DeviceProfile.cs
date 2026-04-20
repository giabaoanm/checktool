namespace SecAudit.Reporting.Models;

/// <summary>
/// Section-1 hardware/network snapshot for the formal report.
/// Built by <see cref="ReportService"/> from the SystemInventory shared by
/// the System Info module + a fresh NetworkInterface enumeration.
/// </summary>
public sealed record DeviceProfile(
    string ComputerName,
    string Cpu,
    string BiosSerial,
    string TotalRam,
    string OperatingSystem,
    IReadOnlyList<NetworkAddress> NetworkAddresses);

public sealed record NetworkAddress(
    string InterfaceName,
    string MacAddress,
    string IPv4,
    string? IPv6);

/// <summary>
/// One auto-remediation outcome surfaced in section 3 of the report.
/// </summary>
public sealed record AppliedAction(
    string FindingId,
    string ActionTitle,
    bool Succeeded,
    string Message,
    bool RebootRequired,
    DateTimeOffset AppliedAt);

/// <summary>
/// One unfixed finding turned into an actionable recommendation for section 4.
/// </summary>
public sealed record Recommendation(
    string FindingId,
    string Title,
    string Severity,
    string Guidance);
