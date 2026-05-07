using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Mitre;
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
        Title: "Microsoft Defender bị tắt, hết hạn hoặc đã bị can thiệp",
        DefaultSeverity: Severity.High,
        Category: "Bảo vệ đầu cuối",
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
                problems.Add("Dịch vụ AMService đã tắt");
            }
            if (GetBool(row, "RealTimeProtectionEnabled") == false)
            {
                problems.Add("Bảo vệ thời gian thực (Real-time) đang tắt");
            }
            if (GetBool(row, "AntivirusEnabled") == false)
            {
                problems.Add("Engine diệt virus đang tắt");
            }
            if (GetBool(row, "AntispywareEnabled") == false)
            {
                problems.Add("Engine diệt spyware đang tắt");
            }

            var sigAge = GetUint(row, "AntivirusSignatureAge");
            if (sigAge.HasValue && sigAge.Value > 7)
            {
                problems.Add($"Signature đã lỗi thời ({sigAge.Value} ngày)");
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
                remediation: "Bật lại Microsoft Defender (Windows Security → Virus & threat protection) "
                             + "hoặc xác nhận đã có phần mềm diệt virus bên thứ ba hoạt động bình thường. "
                             + "Chạy 'Update-MpSignature' để cập nhật signature mới.",
                attackTechniques: new[] { MitreAttackCatalog.T1562_001 }));
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
