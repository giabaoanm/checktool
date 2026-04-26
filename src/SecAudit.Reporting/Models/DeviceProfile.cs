namespace SecAudit.Reporting.Models;

/// <summary>
/// Section-1 hardware/network snapshot for the formal report.
/// Built by <see cref="ReportService"/> from the SystemInventory shared by
/// the System Info module + a fresh NetworkInterface enumeration.
///
/// Extended (2026-04-25) to surface additional baseline facts the SOC operator
/// expected to see in the printed BIÊN BẢN: physical disks, BIOS vendor / release
/// date, CPU core counts. These were collected by the System Info module already
/// but never reached the report.
/// </summary>
public sealed record DeviceProfile(
    string ComputerName,
    string Cpu,
    int CpuCores,
    int CpuLogicalProcessors,
    string BiosSerial,
    string BiosVendor,
    string? BiosVersion,
    DateTimeOffset? BiosReleaseDate,
    string TotalRam,
    string OperatingSystem,
    IReadOnlyList<DiskSummary> Disks,
    IReadOnlyList<NetworkAddress> NetworkAddresses,
    bool TpmPresent,
    string? TpmSpecVersion,
    bool SecureBootEnabled);

public sealed record NetworkAddress(
    string InterfaceName,
    string MacAddress,
    string IPv4,
    string? IPv6);

/// <summary>
/// Per-disk row in section "Thông tin thiết bị". Size formatted by caller (GB).
/// </summary>
public sealed record DiskSummary(
    string Model,
    string InterfaceType,
    string Size,
    string? SerialNumber);

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

// =============================================================================
// License summary (Group A) — surfaces Windows + Office activation state in
// the formal report, regardless of whether a finding fired. The System Info
// module always collects this from WMI SoftwareLicensingProduct; previously
// the data was only read to decide whether to emit a violation finding.
// =============================================================================

/// <summary>
/// Aggregate license posture for the audited host. <see cref="Windows"/> is
/// always present (System Info module always queries Windows SLP). Office may
/// be absent if no Office product is installed.
/// </summary>
public sealed record LicenseSummary(
    LicenseEntry Windows,
    IReadOnlyList<LicenseEntry> Office,
    bool OfficeKmsPicoSuspected,
    IReadOnlyList<string> OfficeKmsPicoEvidence);

/// <summary>
/// One license row: either Windows or one Office SKU. <see cref="StatusCode"/>
/// is the raw WMI SoftwareLicensingProduct.LicenseStatus value (1=Licensed,
/// 0=Unlicensed, 2/3/4/5/6=various grace states). Kept as int so the JSON
/// consumer can correlate with Microsoft's documentation directly.
/// </summary>
public sealed record LicenseEntry(
    string Product,
    int StatusCode,
    string StatusText,
    string Description,
    string? PartialProductKey,
    string? KmsServer,
    bool IsGenuine);

// =============================================================================
// Patch summary (Group A) — overview of installed KB count + CVE database
// freshness so the printed report can answer "how many patches does this
// machine have, when was the CVE rule set last refreshed?".
// =============================================================================

/// <summary>
/// Snapshot built from PatchCveModule's installedKbs set + CveDatabase
/// metadata. Numeric fields stay as int/DateTimeOffset so SIEM consumers can
/// trend them.
/// </summary>
public sealed record PatchSummary(
    int InstalledKbCount,
    int MissingCriticalRuleCount,
    DateTimeOffset? CveDbLastSync,
    bool CveDbStale);

// =============================================================================
// Scan scope (Group B) — surfaces totals that the modules already enumerated
// but only emitted the "suspicious" subset as findings. Without this section
// the report says "5 suspicious autoruns" with no denominator.
// =============================================================================

/// <summary>
/// "Phạm vi quét" section — counts that contextualise findings. Each field is
/// nullable so partial data still renders (e.g. forensics not run → ForensicsRun
/// stays false but autorun counts still print).
/// </summary>
public sealed record ScanScope(
    int? AutorunTotal,
    int? AutorunSuspicious,
    int? ServiceSuspicious,
    int? ScheduledTaskSuspicious,
    int? WmiPersistenceCount,
    bool ForensicsRun,
    string? ForensicsSessionId,
    int? ForensicsTotalFiles,
    long? ForensicsTotalRecords,
    int? ForensicsManifestCount,
    string? ForensicsEvidenceRoot);
