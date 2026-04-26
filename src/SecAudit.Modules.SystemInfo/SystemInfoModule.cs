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
        DisplayName: "Thông tin hệ thống & Bản quyền",
        Description: "Thu thập phần cứng, hệ điều hành, trạng thái bản quyền Windows/Office và phần mềm đã cài.",
        Category: "Kiểm kê",
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
            progress.Report(new ProgressUpdate(Metadata.Id, "Phần cứng & hệ điều hành", 10));
            cancellationToken.ThrowIfCancellationRequested();
            var (hardware, os) = _hardware.Collect();

            progress.Report(new ProgressUpdate(Metadata.Id, "Bản quyền Windows", 30));
            cancellationToken.ThrowIfCancellationRequested();
            var winLicense = _license.CollectWindowsLicense();

            progress.Report(new ProgressUpdate(Metadata.Id, "Bản quyền Office", 45));
            cancellationToken.ThrowIfCancellationRequested();
            var officeLicenses = _license.CollectOfficeLicenses();

            progress.Report(new ProgressUpdate(Metadata.Id, "Kiểm tra dấu hiệu kích hoạt lậu Windows/Office", 60));
            cancellationToken.ThrowIfCancellationRequested();
            // Pass BOTH Windows + Office licenses — KMSpico activates Windows even when
            // Office is not installed, and our previous report missed those cases entirely.
            var (kmsSuspected, kmsEvidence) = _kmsDetector.Detect(winLicense, officeLicenses);

            progress.Report(new ProgressUpdate(Metadata.Id, "Phần mềm đã cài", 80));
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

            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đánh giá", 92));
            EvaluateFindings(inventory, context.MachineName, findings);

            progress.Report(new ProgressUpdate(Metadata.Id, "Hoàn tất", 100));

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
                FailureReason = "Đã bị hủy",
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
                title: "Bản quyền Windows không ở trạng thái Licensed (chính hãng)",
                severity: SeverityForLicense(inv.WindowsLicense.LicenseStatus),
                category: "Bản quyền",
                asset: asset,
                evidence: $"Product='{inv.WindowsLicense.Product}', Status='{inv.WindowsLicense.LicenseStatusText}' ({inv.WindowsLicense.LicenseStatus})",
                remediation: "Kích hoạt Windows bằng product key hợp lệ hoặc đảm bảo máy có thể kết nối tới KMS host của đơn vị.",
                references: RefKmsPlanning));
        }

        if (inv.OfficeKmsPicoSuspected)
        {
            // CRITICAL: this finding fires regardless of WMI LicenseStatus. KMSpico/HEU/AutoKMS
            // explicitly arrange for LicenseStatus=1 — that is the whole point of those tools —
            // so a "genuine" status from WMI is not evidence of legitimacy when artifacts are
            // present on disk. We surface evidence verbatim so the admin can verify each signal.
            sink.Add(Finding.Create(
                id: "SI-OFF-KMS-01",
                title: "Phát hiện dấu hiệu kích hoạt lậu Windows/Office (KMSpico / KMSAuto / HEU / Toolkit / Re-Loader)",
                severity: Severity.High,
                category: "Bản quyền",
                asset: asset,
                evidence: string.Join(" | ", inv.OfficeKmsPicoEvidence),
                remediation: "WMI báo 'Licensed' (LicenseStatus=1) không có nghĩa máy có bản quyền hợp lệ — KMSpico và các tool tương tự "
                             + "đều cố tình làm cho Microsoft licensing service báo Licensed. "
                             + "Hành động: (1) gỡ bỏ tool kích hoạt + scheduled task tương ứng, "
                             + "(2) khôi phục hosts file gốc, (3) chạy `slmgr.vbs /upk` để gỡ key giả, "
                             + "(4) kích hoạt lại bằng key Retail/MAK hoặc đăng nhập M365, "
                             + "(5) sao lưu evidence cho tổ chức/đơn vị quản lý bản quyền.",
                references: RefOfficeVl));
        }

        foreach (var off in inv.OfficeLicenses)
        {
            if (!off.IsGenuine && off.LicenseStatus >= 0)
            {
                sink.Add(Finding.Create(
                    id: "SI-OFF-LIC-01",
                    title: $"Bản quyền Office không ở trạng thái Licensed: {off.Product}",
                    severity: SeverityForLicense(off.LicenseStatus),
                    category: "Bản quyền",
                    asset: asset,
                    evidence: $"Product='{off.Product}', Status='{off.LicenseStatusText}' ({off.LicenseStatus}), KmsServer='{off.KmsServer ?? "(không có)"}'",
                    remediation: "Kích hoạt lại Office qua kênh chính thống (key Retail, đăng nhập M365 hoặc KMS của đơn vị).",
                    references: Array.Empty<string>()));
            }
        }

        // --- Platform security baseline ---
        if (!inv.Hardware.TpmPresent)
        {
            sink.Add(Finding.Create(
                id: "SI-HW-TPM-01",
                title: "Không phát hiện TPM",
                severity: Severity.Medium,
                category: "Nền tảng",
                asset: asset,
                evidence: "Win32_Tpm không trả về instance nào hoặc không truy cập được.",
                remediation: "Bật TPM 2.0 trong UEFI/BIOS. Cần thiết cho BitLocker, Credential Guard và Windows 11.",
                references: RefTpmFundamentals));
        }
        else if (!string.IsNullOrEmpty(inv.Hardware.TpmSpecVersion)
                 && !inv.Hardware.TpmSpecVersion.Contains("2.0", StringComparison.Ordinal))
        {
            sink.Add(Finding.Create(
                id: "SI-HW-TPM-02",
                title: "Có TPM nhưng không phải phiên bản 2.0",
                severity: Severity.Low,
                category: "Nền tảng",
                asset: asset,
                evidence: $"SpecVersion='{inv.Hardware.TpmSpecVersion}'",
                remediation: "Cập nhật firmware TPM lên 2.0 nếu phần cứng hỗ trợ; nếu không, lên kế hoạch thay thế thiết bị.",
                references: Array.Empty<string>()));
        }

        if (!inv.Hardware.SecureBootEnabled)
        {
            sink.Add(Finding.Create(
                id: "SI-HW-SB-01",
                title: "Secure Boot đang bị tắt",
                severity: Severity.High,
                category: "Nền tảng",
                asset: asset,
                evidence: @"Registry HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled != 1",
                remediation: "Bật Secure Boot trong UEFI. Bảo vệ chuỗi khởi động trước các loại malware kiểu bootkit.",
                references: RefSecureBoot));
        }

        // --- Hardware / OS sanity ---
        if (inv.Hardware.TotalPhysicalMemoryBytes > 0 && inv.Hardware.TotalPhysicalMemoryBytes < 4L * 1024 * 1024 * 1024)
        {
            sink.Add(Finding.Create(
                id: "SI-HW-RAM-01",
                title: "RAM hệ thống dưới 4 GB",
                severity: Severity.Info,
                category: "Phần cứng",
                asset: asset,
                evidence: $"TotalPhysicalMemoryBytes={inv.Hardware.TotalPhysicalMemoryBytes}",
                remediation: "Cân nhắc nâng cấp RAM — Windows hiện đại kèm EDR sẽ chạy ì với cấu hình thấp như vậy.",
                references: Array.Empty<string>()));
        }

        if (inv.OperatingSystem.BuildNumber.Length > 0
            && int.TryParse(inv.OperatingSystem.BuildNumber, out var build)
            && build < 19045)
        {
            sink.Add(Finding.Create(
                id: "SI-OS-BUILD-01",
                title: "OS build thấp hơn Windows 10 22H2 (19045)",
                severity: Severity.Medium,
                category: "Nền tảng",
                asset: asset,
                evidence: $"Caption='{inv.OperatingSystem.Caption}', Build={build}",
                remediation: "Nâng cấp lên Windows 10 22H2 hoặc Windows 11. Các bản feature update cũ hơn không còn nhận bản vá bảo mật.",
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
