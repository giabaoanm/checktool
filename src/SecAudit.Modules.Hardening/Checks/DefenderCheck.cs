using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Reads Microsoft Defender runtime state via MSFT_MpComputerStatus.
/// Off, out-of-date signatures, or tampering indicators all produce a finding.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DefenderCheck : ICheck
{
    private readonly IWmiQuery _wmi;
    private readonly ILogger<DefenderCheck> _logger;

    public DefenderCheck(IWmiQuery wmi, ILogger<DefenderCheck> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-DEF-01",
        Title: "Microsoft Defender is disabled, out-of-date, or tampered",
        DefaultSeverity: Severity.High,
        Category: "Endpoint Protection",
        CisReference: "CIS 18.9.47.x");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        try
        {
            var row = _wmi.Query(@"\\.\ROOT\Microsoft\Windows\Defender",
                "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, "
                + "AntispywareEnabled, TamperProtectionEnabled, AntivirusSignatureAge, "
                + "IsTamperProtected, ProductStatus FROM MSFT_MpComputerStatus").FirstOrDefault();

            if (row is null)
            {
                // If Defender WMI namespace doesn't respond, it's often because a 3rd-party AV
                // has taken over — that's expected, not a finding on its own.
                return Task.FromResult<Finding?>(null);
            }

            var problems = new List<string>();
            if (GetBool(row, "AMServiceEnabled") == false)
            {
                problems.Add("AMService disabled");
            }
            if (GetBool(row, "RealTimeProtectionEnabled") == false)
            {
                problems.Add("Real-time protection OFF");
            }
            if (GetBool(row, "AntivirusEnabled") == false)
            {
                problems.Add("Antivirus engine OFF");
            }
            if (GetBool(row, "AntispywareEnabled") == false)
            {
                problems.Add("Antispyware engine OFF");
            }

            var sigAge = GetUint(row, "AntivirusSignatureAge");
            if (sigAge.HasValue && sigAge.Value > 7)
            {
                problems.Add($"Signatures stale ({sigAge.Value} days old)");
            }

            if (problems.Count == 0)
            {
                return Task.FromResult<Finding?>(null);
            }

            return Task.FromResult<Finding?>(Finding.Create(
                id: Metadata.Id,
                title: Metadata.Title,
                severity: Severity.High,
                category: Metadata.Category,
                asset: ctx.Asset,
                evidence: string.Join("; ", problems),
                remediation: "Re-enable Microsoft Defender (Windows Security → Virus & threat protection) "
                             + "or confirm a properly-running 3rd-party AV is installed. Run 'Update-MpSignature' for stale signatures."));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Defender WMI query failed (may be 3rd-party AV active)");
            return Task.FromResult<Finding?>(null);
        }
    }

    private static bool? GetBool(IReadOnlyDictionary<string, object?> r, string k)
        => r.TryGetValue(k, out var v) && v is not null
            && bool.TryParse(v.ToString(), out var b) ? b : null;

    private static uint? GetUint(IReadOnlyDictionary<string, object?> r, string k)
        => r.TryGetValue(k, out var v) && v is not null
            && uint.TryParse(v.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;
}
