using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Inventories every firewall product registered with the Windows Security Center
/// (<c>root\SecurityCenter2 → FirewallProduct</c>) and produces an informational finding
/// describing the protection landscape.
///
/// <para>
/// Why this matters in the field: when <see cref="FirewallCheck"/> reports
/// <i>"Windows Defender Firewall is OFF"</i>, that is sometimes a real misconfiguration —
/// but on enterprise endpoints it is more often the expected side-effect of installing a
/// third-party endpoint firewall (Kaspersky Endpoint Security, ESET, Sophos, McAfee…).
/// Microsoft's WFP cleanly hands control to the third-party WPP filter, the Windows
/// Defender Firewall service goes idle, and HD-FW-01 fires what looks like a Critical
/// alarm. Without context the SOC operator cannot tell those two cases apart.
/// </para>
///
/// <para>
/// This check exists to provide that context. It enumerates <i>all</i> registered firewall
/// providers and reports them. Severity escalation:
/// <list type="bullet">
///   <item>0 products registered → <c>High</c> ("máy không có firewall nào đăng ký với Security Center" — extremely rare and almost always a sign that Action Center is broken or has been tampered with).</item>
///   <item>≥ 1 third-party product → <c>Low</c> (informational; the admin should cross-reference with HD-FW-01).</item>
///   <item>Only Windows Defender Firewall registered → no finding (the normal case; HD-FW-01 covers its state).</item>
/// </list>
/// </para>
///
/// <para>
/// We intentionally do not attempt to decode the obscure <c>productState</c> bitfield —
/// the schema is undocumented and shifts between Windows builds. Listing display names is
/// enough signal for the analyst; they can verify state via the product's own UI.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ThirdPartyFirewallCheck : ICheck
{
    private const string ProfileRoot =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    private readonly IWmiQuery _wmi;
    private readonly IRegistryReader _registry;
    private readonly ILogger<ThirdPartyFirewallCheck> _logger;

    public ThirdPartyFirewallCheck(
        IWmiQuery wmi,
        IRegistryReader registry,
        ILogger<ThirdPartyFirewallCheck> logger)
    {
        _wmi = wmi;
        _registry = registry;
        _logger = logger;
    }

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-FW-05",
        Title: "Trạng thái đăng ký firewall với Windows Security Center",
        DefaultSeverity: Severity.Low,
        Category: "Tường lửa máy trạm",
        CisReference: "Bổ sung — không có CIS tương đương");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows;
        try
        {
            rows = _wmi.Query(@"\\.\ROOT\SecurityCenter2",
                "SELECT displayName, productState, pathToSignedProductExe FROM FirewallProduct").ToList();
        }
        catch (Exception ex)
        {
            // SecurityCenter2 may be missing on Windows Server SKUs (Server 2019/2022 do
            // not ship the consumer Action Center). That is not a finding for our scope.
            _logger.LogDebug(ex, "SecurityCenter2 FirewallProduct query failed (likely Server SKU)");
            return Task.FromResult<Finding?>(null);
        }

        if (rows.Count == 0)
        {
            if (WindowsFirewallProfilesEnabled())
            {
                return Task.FromResult<Finding?>(Finding.Create(
                    id: Metadata.Id,
                    title: "Windows Security Center chưa liệt kê firewall, nhưng Windows Firewall registry đang bật",
                    severity: Severity.Info,
                    category: Metadata.Category,
                    asset: ctx.Asset,
                    evidence: "ROOT\\SecurityCenter2 → FirewallProduct trả về 0 hàng, nhưng EnableFirewall không tắt trên Domain/Private/Public profile. "
                              + "Đây thường là Security Center/WMI chưa cập nhật sau khi cài mới hoặc cập nhật Windows, không phải bằng chứng tắt firewall.",
                    remediation: "Kiểm tra nhanh bằng 'Get-NetFirewallProfile'. Nếu Domain/Private/Public đều Enabled=True thì không cần xử lý khẩn cấp; có thể restart dịch vụ Security Center để đồng bộ lại Action Center."));
            }

            return Task.FromResult<Finding?>(Finding.Create(
                id: Metadata.Id,
                title: "Không có firewall nào đăng ký với Windows Security Center",
                severity: Severity.High,
                category: Metadata.Category,
                asset: ctx.Asset,
                evidence: "ROOT\\SecurityCenter2 → FirewallProduct trả về 0 hàng. "
                          + "Action Center không thấy bất kỳ firewall nào đang quản lý máy.",
                remediation: "Khởi động lại dịch vụ Security Center (services.msc → 'Security Center' → Restart). "
                             + "Nếu vẫn trống: kiểm tra xem AV/firewall vừa cài có hoàn tất chưa, "
                             + "hoặc bật lại Windows Defender Firewall (xem HD-FW-01)."));
        }

        var products = new List<(string Name, string Path)>();
        foreach (var row in rows)
        {
            var name = (row.TryGetValue("displayName", out var n) ? n?.ToString() : null) ?? "(không tên)";
            var exe = (row.TryGetValue("pathToSignedProductExe", out var p) ? p?.ToString() : null) ?? string.Empty;
            products.Add((name, exe));
        }

        var thirdParty = products
            .Where(p => !IsBuiltInWindowsFirewall(p.Name))
            .ToList();

        if (thirdParty.Count == 0)
        {
            // Only Windows Defender Firewall is registered — normal case, HD-FW-01 owns it.
            return Task.FromResult<Finding?>(null);
        }

        var lines = products
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .Select(p => $"  • {p.Name}"
                         + (string.IsNullOrEmpty(p.Path) ? string.Empty : $" → {p.Path}"));
        var evidence = string.Format(
            CultureInfo.InvariantCulture,
            "Phát hiện {0} firewall đăng ký ({1} bên thứ ba):\n{2}",
            products.Count,
            thirdParty.Count,
            string.Join("\n", lines));

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: "Có firewall bên thứ ba đăng ký với Windows Security Center",
            severity: Severity.Low,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: evidence,
            remediation: "Đây là cảnh báo tham khảo. Nếu HD-FW-01 báo Windows Firewall TẮT mà bạn "
                         + "thấy firewall bên thứ ba ở đây đang chạy → đó là hành vi bình thường "
                         + "(sản phẩm bên thứ ba đã thay thế Windows Firewall). "
                         + "Nếu KHÔNG cài chủ động sản phẩm nào ngoài Windows: kiểm tra ngay danh sách "
                         + "trên — có thể là phần mềm không mong muốn (PUA) đang gắn vào Security Center."));
    }

    /// <summary>
    /// Windows Security Center registers Microsoft's own firewall under one of two display
    /// names depending on the Windows build. Anything else is "third party" for our purposes.
    /// </summary>
    private static bool IsBuiltInWindowsFirewall(string displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            return false;
        }
        return displayName.Equals("Windows Firewall", StringComparison.OrdinalIgnoreCase)
            || displayName.Equals("Windows Defender Firewall", StringComparison.OrdinalIgnoreCase);
    }

    private bool WindowsFirewallProfilesEnabled()
    {
        var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
        foreach (var profile in profiles)
        {
            try
            {
                var enabled = _registry.GetValue(
                    RegistryHive.LocalMachine,
                    $@"{ProfileRoot}\{profile}",
                    "EnableFirewall") as int?;
                if (enabled == 0)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Could not read firewall profile {Profile}", profile);
                return false;
            }
        }

        return true;
    }
}
