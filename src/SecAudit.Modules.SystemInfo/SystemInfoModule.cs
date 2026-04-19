using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.SystemInfo.Collectors;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.SystemInfo;

/// <summary>
/// Iteration 1 module. Inventories hardware, OS, license state, and installed software.
/// Emits findings for: Windows non-genuine, Office KMSpico suspicion, TPM absent,
/// Secure Boot disabled, and for a handful of license edge cases. Shares the collected
/// SystemInventory via ScanContext for downstream modules (Patch/CVE, Hardening).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SystemInfoModule : IAuditModule
{
    public const string SharedInventoryKey = "SystemInfo.Inventory";

    private static readonly string[] RefKmsPlanning =
        { "https://learn.microsoft.com/windows-server/get-started/kms-activation-planning" };
    private static readonly string[] RefOfficeVl =
        { "https://learn.microsoft.com/deployoffice/vlactivation/tools-to-manage-volume-activation-of-office" };
    private static readonly string[] RefTpmFundamentals =
        { "https://learn.microsoft.com/windows/security/hardware-security/tpm/tpm-fundamentals" };
    private static readonly string[] RefSecureBoot =
        { "https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot" };
    private static readonly string[] RefWin10Release =
        { "https://learn.microsoft.com/windows/release-health/windows10-release-information" };

    private readonly HardwareInventory _hardware;
    private readonly LicenseChecker _license;
    private readonly OfficeKmsPicoDetector _kmsDetector;
    private readonly SoftwareInventory _software;
    private readonly ILogger<SystemInfoModule> _logger;

    public SystemInfoModule(
        HardwareInventory hardware,
        LicenseChecker license,
        OfficeKmsPicoDetector kmsDetector,
        SoftwareInventory software,
        ILogger<SystemInfoModule> logger)
    {
        _hardware = hardware;
        _license = license;
        _kmsDetector = kmsDetector;
        _software = software;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "system-info",
        DisplayName: "System Info & License",
        Description: "Hardware, OS, Windows/Office license status, installed software.",
        Category: "Inventory",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: false,
        DisplayOrder: 10);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();

        try
        {
            progress.Report(new ProgressUpdate(Metadata.Id, "Hardware & OS", 10));
            cancellationToken.ThrowIfCancellationRequested();
            var (hardware, os) = _hardware.Collect();

            progress.Report(new ProgressUpdate(Metadata.Id, "Windows license", 30));
            cancellationToken.ThrowIfCancellationRequested();
            var winLicense = _license.CollectWindowsLicense();

            progress.Report(new ProgressUpdate(Metadata.Id, "Office license", 45));
            cancellationToken.ThrowIfCancellationRequested();
            var officeLicenses = _license.CollectOfficeLicenses();

            progress.Report(new ProgressUpdate(Metadata.Id, "Office activation heuristics", 60));
            cancellationToken.ThrowIfCancellationRequested();
            var (kmsSuspected, kmsEvidence) = _kmsDetector.Detect(officeLicenses);

            progress.Report(new ProgressUpdate(Metadata.Id, "Installed software", 80));
            cancellationToken.ThrowIfCancellationRequested();
            var software = _software.Collect();

            var inventory = new SystemInventory(
                Hardware: hardware,
                OperatingSystem: os,
                WindowsLicense: winLicense,
                OfficeLicenses: officeLicenses,
                OfficeKmsPicoSuspected: kmsSuspected,
                OfficeKmsPicoEvidence: kmsEvidence,
                Software: software);

            context.SetShared(SharedInventoryKey, inventory);

            progress.Report(new ProgressUpdate(Metadata.Id, "Evaluating", 92));
            EvaluateFindings(inventory, context.MachineName, findings);

            progress.Report(new ProgressUpdate(Metadata.Id, "Done", 100));

            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            });
        }
        catch (OperationCanceledException)
        {
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = "Cancelled",
                Findings = findings
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SystemInfoModule failed");
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = ex.Message,
                Findings = findings
            });
        }
    }

    private static void EvaluateFindings(SystemInventory inv, string asset, List<object> sink)
    {
        // --- Licensing ---
        if (!inv.WindowsLicense.IsGenuine && inv.WindowsLicense.LicenseStatus >= 0)
        {
            sink.Add(Finding.Create(
                id: "SI-WIN-LIC-01",
                title: "Windows license is not in a Licensed (genuine) state",
                severity: SeverityForLicense(inv.WindowsLicense.LicenseStatus),
                category: "Licensing",
                asset: asset,
                evidence: $"Product='{inv.WindowsLicense.Product}', Status='{inv.WindowsLicense.LicenseStatusText}' ({inv.WindowsLicense.LicenseStatus})",
                remediation: "Activate Windows with a valid product key or ensure the device can reach its KMS host.",
                references: RefKmsPlanning));
        }

        if (inv.OfficeKmsPicoSuspected)
        {
            sink.Add(Finding.Create(
                id: "SI-OFF-KMS-01",
                title: "Office activation shows KMSpico / AutoKMS-style signals",
                severity: Severity.High,
                category: "Licensing",
                asset: asset,
                evidence: string.Join(" | ", inv.OfficeKmsPicoEvidence),
                remediation: "Remove unauthorized activation tooling and re-license Office with a valid key or Microsoft 365 tenant. "
                             + "Each piece of evidence is independent — verify each before acting.",
                references: RefOfficeVl));
        }

        foreach (var off in inv.OfficeLicenses)
        {
            if (!off.IsGenuine && off.LicenseStatus >= 0)
            {
                sink.Add(Finding.Create(
                    id: "SI-OFF-LIC-01",
                    title: $"Office license not in Licensed state: {off.Product}",
                    severity: SeverityForLicense(off.LicenseStatus),
                    category: "Licensing",
                    asset: asset,
                    evidence: $"Product='{off.Product}', Status='{off.LicenseStatusText}' ({off.LicenseStatus}), KmsServer='{off.KmsServer ?? "(none)"}'",
                    remediation: "Reactivate Office through proper channels (retail key, M365 sign-in, or corporate KMS).",
                    references: Array.Empty<string>()));
            }
        }

        // --- Platform security baseline ---
        if (!inv.Hardware.TpmPresent)
        {
            sink.Add(Finding.Create(
                id: "SI-HW-TPM-01",
                title: "TPM not detected",
                severity: Severity.Medium,
                category: "Platform",
                asset: asset,
                evidence: "Win32_Tpm returned no instance or was inaccessible.",
                remediation: "Enable TPM 2.0 in UEFI firmware. Required for BitLocker, Credential Guard, and Windows 11.",
                references: RefTpmFundamentals));
        }
        else if (!string.IsNullOrEmpty(inv.Hardware.TpmSpecVersion)
                 && !inv.Hardware.TpmSpecVersion.Contains("2.0", StringComparison.Ordinal))
        {
            sink.Add(Finding.Create(
                id: "SI-HW-TPM-02",
                title: "TPM present but not version 2.0",
                severity: Severity.Low,
                category: "Platform",
                asset: asset,
                evidence: $"SpecVersion='{inv.Hardware.TpmSpecVersion}'",
                remediation: "Update TPM firmware to 2.0 where hardware supports it; plan replacement otherwise.",
                references: Array.Empty<string>()));
        }

        if (!inv.Hardware.SecureBootEnabled)
        {
            sink.Add(Finding.Create(
                id: "SI-HW-SB-01",
                title: "Secure Boot is disabled",
                severity: Severity.High,
                category: "Platform",
                asset: asset,
                evidence: @"Registry HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled != 1",
                remediation: "Enable Secure Boot in UEFI. Protects boot chain against bootkit-class malware.",
                references: RefSecureBoot));
        }

        // --- Hardware / OS sanity ---
        if (inv.Hardware.TotalPhysicalMemoryBytes > 0 && inv.Hardware.TotalPhysicalMemoryBytes < 4L * 1024 * 1024 * 1024)
        {
            sink.Add(Finding.Create(
                id: "SI-HW-RAM-01",
                title: "System has less than 4 GB RAM",
                severity: Severity.Info,
                category: "Hardware",
                asset: asset,
                evidence: $"TotalPhysicalMemoryBytes={inv.Hardware.TotalPhysicalMemoryBytes}",
                remediation: "Consider RAM upgrade — modern Windows + EDR will struggle.",
                references: Array.Empty<string>()));
        }

        if (inv.OperatingSystem.BuildNumber.Length > 0
            && int.TryParse(inv.OperatingSystem.BuildNumber, out var build)
            && build < 19045)
        {
            sink.Add(Finding.Create(
                id: "SI-OS-BUILD-01",
                title: "OS build is below Windows 10 22H2 (19045)",
                severity: Severity.Medium,
                category: "Platform",
                asset: asset,
                evidence: $"Caption='{inv.OperatingSystem.Caption}', Build={build}",
                remediation: "Upgrade to Windows 10 22H2 or Windows 11. Earlier feature updates no longer receive security fixes.",
                references: RefWin10Release));
        }
    }

    private static Severity SeverityForLicense(int status) => status switch
    {
        0 => Severity.High,      // Unlicensed
        2 => Severity.Medium,    // OOB grace
        3 => Severity.Medium,    // OOT grace
        4 => Severity.High,      // Non-genuine grace
        5 => Severity.Medium,    // Notification
        6 => Severity.Low,       // Extended grace
        _ => Severity.Low
    };
}
