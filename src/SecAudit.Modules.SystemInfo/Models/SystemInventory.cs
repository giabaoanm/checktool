namespace SecAudit.Modules.SystemInfo.Models;

public sealed record HardwareInfo(
    string Manufacturer,
    string Model,
    string SerialNumber,
    string BiosVendor,
    string BiosVersion,
    DateTimeOffset? BiosReleaseDate,
    string CpuName,
    int CpuCores,
    int CpuLogicalProcessors,
    long TotalPhysicalMemoryBytes,
    IReadOnlyList<DiskDriveInfo> Disks,
    bool TpmPresent,
    string? TpmSpecVersion,
    bool SecureBootEnabled);

public sealed record DiskDriveInfo(
    string Model,
    string InterfaceType,
    long SizeBytes,
    string? SerialNumber);

public sealed record OsInfo(
    string Caption,
    string Version,
    string BuildNumber,
    string DisplayVersion,
    string InstallDate,
    string Architecture,
    string LastBootUpTime);

public sealed record LicenseInfo(
    string Product,
    string LicenseStatusText,
    int LicenseStatus,
    string Description,
    string? PartialProductKey,
    string? KmsServer,
    bool IsGenuine);

public sealed record InstalledSoftware(
    string DisplayName,
    string? Version,
    string? Publisher,
    string? InstallDate,
    string? InstallLocation,
    string Source);

public sealed record SystemInventory(
    HardwareInfo Hardware,
    OsInfo OperatingSystem,
    LicenseInfo WindowsLicense,
    IReadOnlyList<LicenseInfo> OfficeLicenses,
    bool OfficeKmsPicoSuspected,
    IReadOnlyList<string> OfficeKmsPicoEvidence,
    IReadOnlyList<InstalledSoftware> Software);
