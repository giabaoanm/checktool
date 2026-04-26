using System.Globalization;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Modules.PatchCve;
using SecAudit.Modules.RemoteAccess;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.App.ViewModels;

/// <summary>
/// Maps the rich raw snapshots that modules publish into <c>ScanContext.SharedState</c>
/// (SystemInventory, PatchSnapshot, RemoteAccessSnapshot, ForensicsResult) into the flat
/// <see cref="DeviceProfile"/>/<see cref="LicenseSummary"/>/<see cref="PatchSummary"/>/<see cref="ScanScope"/>
/// records the report writers consume.
///
/// Lives in the App project (not Reporting) because Reporting must NOT depend on the
/// module assemblies — keeps the dependency graph one-way (Modules → App → Reporting).
/// CLI duplicates the same logic in <c>SecAudit.Cli.Program</c> for the same reason.
/// All methods are null-tolerant: a missing snapshot returns null so the writer omits
/// the section.
/// </summary>
internal static class ReportSectionBuilder
{
    public static DeviceProfile BuildDeviceProfile(SystemInventory? inv)
    {
        var nics = NetworkAddressCollector.Collect();
        if (inv is null)
        {
            return new DeviceProfile(
                ComputerName: Environment.MachineName,
                Cpu: "(unknown)",
                CpuCores: 0,
                CpuLogicalProcessors: 0,
                BiosSerial: "(unknown)",
                BiosVendor: "(unknown)",
                BiosVersion: null,
                BiosReleaseDate: null,
                TotalRam: "(unknown)",
                OperatingSystem: Environment.OSVersion.VersionString,
                Disks: Array.Empty<DiskSummary>(),
                NetworkAddresses: nics,
                TpmPresent: false,
                TpmSpecVersion: null,
                SecureBootEnabled: false);
        }
        var ramGb = inv.Hardware.TotalPhysicalMemoryBytes / (1024.0 * 1024 * 1024);
        var disks = inv.Hardware.Disks
            .Select(d => new DiskSummary(
                Model: d.Model,
                InterfaceType: d.InterfaceType,
                Size: FormatGb(d.SizeBytes),
                SerialNumber: d.SerialNumber))
            .ToArray();
        return new DeviceProfile(
            ComputerName: Environment.MachineName,
            Cpu: $"{inv.Hardware.CpuName} ({inv.Hardware.CpuCores}C/{inv.Hardware.CpuLogicalProcessors}T)",
            CpuCores: inv.Hardware.CpuCores,
            CpuLogicalProcessors: inv.Hardware.CpuLogicalProcessors,
            BiosSerial: string.IsNullOrWhiteSpace(inv.Hardware.SerialNumber) ? "(không có)" : inv.Hardware.SerialNumber,
            BiosVendor: string.IsNullOrWhiteSpace(inv.Hardware.BiosVendor) ? "(không xác định)" : inv.Hardware.BiosVendor,
            BiosVersion: string.IsNullOrWhiteSpace(inv.Hardware.BiosVersion) ? null : inv.Hardware.BiosVersion,
            BiosReleaseDate: inv.Hardware.BiosReleaseDate,
            TotalRam: ramGb >= 0.5 ? $"{ramGb:0.0} GB" : "(unknown)",
            OperatingSystem: $"{inv.OperatingSystem.Caption} build {inv.OperatingSystem.BuildNumber} ({inv.OperatingSystem.DisplayVersion})",
            Disks: disks,
            NetworkAddresses: nics,
            TpmPresent: inv.Hardware.TpmPresent,
            TpmSpecVersion: inv.Hardware.TpmSpecVersion,
            SecureBootEnabled: inv.Hardware.SecureBootEnabled);
    }

    public static LicenseSummary? BuildLicenseSummary(SystemInventory? inv)
    {
        if (inv is null) { return null; }
        return new LicenseSummary(
            Windows: ToEntry(inv.WindowsLicense),
            Office: inv.OfficeLicenses.Select(ToEntry).ToArray(),
            OfficeKmsPicoSuspected: inv.OfficeKmsPicoSuspected,
            OfficeKmsPicoEvidence: inv.OfficeKmsPicoEvidence);
    }

    public static PatchSummary? BuildPatchSummary(PatchSnapshot? snap)
    {
        if (snap is null) { return null; }
        return new PatchSummary(
            InstalledKbCount: snap.InstalledKbCount,
            MissingCriticalRuleCount: snap.MissingCriticalRuleCount,
            CveDbLastSync: snap.CveDbLastSync,
            CveDbStale: snap.CveDbStale);
    }

    /// <summary>
    /// Combines remote-access and (optional) log-forensics snapshots into a single
    /// "Phạm vi quét" object. If both are null, returns null so the section is omitted.
    /// </summary>
    public static ScanScope? BuildScanScope(RemoteAccessSnapshot? ra, ForensicsResult? forensics)
    {
        if (ra is null && forensics is null) { return null; }
        return new ScanScope(
            AutorunTotal: ra?.AutorunTotal,
            AutorunSuspicious: ra?.AutorunSuspicious,
            ServiceSuspicious: ra?.ServiceSuspicious,
            ScheduledTaskSuspicious: ra?.ScheduledTaskSuspicious,
            WmiPersistenceCount: ra?.WmiPersistenceCount,
            ForensicsRun: forensics is not null,
            ForensicsSessionId: forensics?.SessionId,
            ForensicsTotalFiles: forensics?.TotalFiles,
            ForensicsTotalRecords: forensics?.TotalRecords,
            ForensicsManifestCount: forensics?.Manifest.Count,
            ForensicsEvidenceRoot: forensics?.EvidenceRoot);
    }

    private static LicenseEntry ToEntry(LicenseInfo li) => new(
        Product: li.Product,
        StatusCode: li.LicenseStatus,
        StatusText: li.LicenseStatusText,
        Description: li.Description,
        PartialProductKey: li.PartialProductKey,
        KmsServer: li.KmsServer,
        IsGenuine: li.IsGenuine);

    private static string FormatGb(long bytes)
    {
        var gb = bytes / (1024.0 * 1024 * 1024);
        return gb >= 1
            ? gb.ToString("0.0", CultureInfo.InvariantCulture) + " GB"
            : (bytes / (1024.0 * 1024)).ToString("0", CultureInfo.InvariantCulture) + " MB";
    }
}
