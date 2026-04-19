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
        Title: "System drive is not protected by BitLocker",
        DefaultSeverity: Severity.High,
        Category: "Disk Encryption",
        CisReference: "CIS 18.9.11.x");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken _)
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
                    title: "BitLocker status could not be determined",
                    severity: Severity.Medium,
                    category: Metadata.Category,
                    asset: ctx.Asset,
                    evidence: "Win32_EncryptableVolume returned no instance for " + sysDrive,
                    remediation: "Windows Home editions do not support BitLocker; consider upgrading to Pro and enabling BitLocker on the OS drive."));
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
                evidence: $"DriveLetter={sysDrive}, ProtectionStatus={protection} (0=Off,1=On,2=Unknown), ConversionStatus={conversion}",
                remediation: "Enable BitLocker on the OS drive: manage-bde -on " + sysDrive
                             + " -recoverypassword. Store the recovery key in AD/Entra ID or an offline vault."));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "BitLocker check failed");
            return Task.FromResult<Finding?>(null);
        }
    }
}
