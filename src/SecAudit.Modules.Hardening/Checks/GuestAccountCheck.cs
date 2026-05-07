using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Mitre;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class GuestAccountCheck : ICheck
{
    private readonly IWmiQuery _wmi;
    private readonly ILogger<GuestAccountCheck> _logger;

    public GuestAccountCheck(IWmiQuery wmi, ILogger<GuestAccountCheck> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-ACCT-GUEST-01",
        Title: "Tài khoản Guest mặc định đang bật",
        DefaultSeverity: Severity.High,
        Category: "Tài khoản & UAC",
        CisReference: "CIS 2.3.1.3");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        try
        {
            // The well-known Guest account has SID ending with -501. Safer than matching localized name.
            var rows = _wmi.Query(@"\\.\ROOT\CIMV2",
                "SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount=TRUE");

            foreach (var row in rows)
            {
                var sid = row.TryGetValue("SID", out var s) ? s?.ToString() : null;
                if (sid is null || !sid.EndsWith("-501", StringComparison.Ordinal))
                {
                    continue;
                }

                var disabledText = row.TryGetValue("Disabled", out var d) ? d?.ToString() : "False";
                var disabled = bool.TryParse(disabledText, out var db) && db;
                var name = row.TryGetValue("Name", out var n) ? n?.ToString() : "Guest";

                if (disabled)
                {
                    return Task.FromResult<Finding?>(null);
                }

                return Task.FromResult<Finding?>(Finding.Create(
                    id: Metadata.Id,
                    title: Metadata.Title,
                    severity: Severity.High,
                    category: Metadata.Category,
                    asset: ctx.Asset,
                    evidence: $"Name={name}, SID={sid}, Disabled=False",
                    remediation: "Vô hiệu hóa tài khoản Guest: net user Guest /active:no",
                    attackTechniques: new[] { MitreAttackCatalog.T1078 }));
            }

            return Task.FromResult<Finding?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Guest account WMI query failed");
            return Task.FromResult<Finding?>(null);
        }
    }
}
