using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Inspects Win32_EncryptableVolume for the OS volume. Flags if not protected.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BitLockerCheck : ICheck
{
    private readonly IWmiQuery _wmi;
    private readonly ILogger<BitLockerCheck> _logger;

    public BitLockerCheck(IWmiQuery wmi, ILogger<BitLockerCheck> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-BL-01",
        Title: "Ổ đĩa hệ thống chưa được BitLocker bảo vệ",
        DefaultSeverity: Severity.High,
        Category: "Mã hóa ổ đĩa",
        CisReference: "CIS 18.9.11.x");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        try
        {
            var sysDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            var row = _wmi.Query(@"\\.\ROOT\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod "
                + $"FROM Win32_EncryptableVolume WHERE DriveLetter='{sysDrive}'").FirstOrDefault();

            if (row is null)
            {
                // WMI namespace unreachable → Home SKUs don't ship BitLocker; flag softly.
                return Task.FromResult<Finding?>(Finding.Create(
                    id: Metadata.Id,
                    title: "Không xác định được trạng thái BitLocker",
                    severity: Severity.Medium,
                    category: Metadata.Category,
                    asset: ctx.Asset,
                    evidence: "Win32_EncryptableVolume không trả về instance nào cho " + sysDrive,
                    remediation: "Windows bản Home không hỗ trợ BitLocker; cân nhắc nâng cấp lên bản Pro và bật BitLocker cho ổ hệ thống."));
            }

            var protectionRaw = row.TryGetValue("ProtectionStatus", out var ps) ? ps?.ToString() : null;
            var protection = int.TryParse(protectionRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pv) ? pv : -1;
            // 0 = Unprotected, 1 = Protection On, 2 = Protection Unknown.

            if (protection == 1)
            {
                return Task.FromResult<Finding?>(null);
            }

            var conversion = row.TryGetValue("ConversionStatus", out var c) ? c?.ToString() : "?";
            return Task.FromResult<Finding?>(Finding.Create(
                id: Metadata.Id,
                title: Metadata.Title,
                severity: Severity.High,
                category: Metadata.Category,
                asset: ctx.Asset,
                evidence: $"DriveLetter={sysDrive}, ProtectionStatus={protection} (0=Tắt, 1=Bật, 2=Không rõ), ConversionStatus={conversion}",
                remediation: "Bật BitLocker cho ổ hệ thống: manage-bde -on " + sysDrive
                             + " -recoverypassword. Lưu recovery key vào AD/Entra ID hoặc két offline của đơn vị."));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "BitLocker check failed");
            return Task.FromResult<Finding?>(null);
        }
    }
}
