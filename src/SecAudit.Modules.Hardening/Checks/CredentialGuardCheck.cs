using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Credential Guard runs LSA isolated in a VBS container so secrets can't be extracted
/// even with SYSTEM + kernel access. Reports Win32_DeviceGuard.SecurityServicesRunning.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CredentialGuardCheck : ICheck
{
    private readonly IWmiQuery _wmi;
    private readonly ILogger<CredentialGuardCheck> _logger;

    public CredentialGuardCheck(IWmiQuery wmi, ILogger<CredentialGuardCheck> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-CG-01",
        Title: "Credential Guard / VBS is not running",
        DefaultSeverity: Severity.Medium,
        Category: "Credential Protection",
        CisReference: "CIS 18.9.45.x");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        try
        {
            var row = _wmi.Query(@"\\.\ROOT\Microsoft\Windows\DeviceGuard",
                "SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning FROM Win32_DeviceGuard").FirstOrDefault();

            if (row is null)
            {
                return Task.FromResult<Finding?>(null);
            }

            var vbsStatus = row.TryGetValue("VirtualizationBasedSecurityStatus", out var v) ? v?.ToString() : "0";
            var running = row.TryGetValue("SecurityServicesRunning", out var s) && s is object sObj
                ? FlattenArray(sObj) : string.Empty;

            // 2 = VBS enabled AND running. SecurityServicesRunning should contain 1 (CG).
            var vbs = int.TryParse(vbsStatus, out var vv) ? vv : 0;
            var hasCg = running.Split(',').Any(x => x.Trim() == "1");

            if (vbs == 2 && hasCg)
            {
                return Task.FromResult<Finding?>(null);
            }

            return Task.FromResult<Finding?>(Finding.Create(
                id: Metadata.Id,
                title: Metadata.Title,
                severity: Severity.Medium,
                category: Metadata.Category,
                asset: ctx.Asset,
                evidence: $"VirtualizationBasedSecurityStatus={vbs}, SecurityServicesRunning=[{running}]",
                remediation: "Enable Credential Guard via group policy: Computer Configuration → Admin Templates → System → Device Guard → "
                             + "'Turn On Virtualization Based Security' → Enabled, Credential Guard Configuration=Enabled with UEFI lock. "
                             + "Requires TPM 2.0, Secure Boot, and CPU virt extensions."));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DeviceGuard WMI query failed");
            return Task.FromResult<Finding?>(null);
        }
    }

    private static string FlattenArray(object value)
    {
        if (value is System.Collections.IEnumerable enumerable && value is not string)
        {
            var parts = new List<string>();
            foreach (var item in enumerable)
            {
                parts.Add(item?.ToString() ?? "");
            }
            return string.Join(",", parts);
        }
        return value.ToString() ?? string.Empty;
    }
}
