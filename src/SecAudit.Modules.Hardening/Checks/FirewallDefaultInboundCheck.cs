using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Verifies <c>DefaultInboundAction = Block (1)</c> on every firewall profile.
///
/// <para>
/// On a healthy Windows 10/11 baseline this value is either absent (Windows defaults to
/// Block) or explicitly <c>1</c>. A value of <c>0</c> means the profile silently accepts
/// every inbound connection that no rule explicitly blocks — equivalent to running with
/// the firewall service on but with no firewall at all. RATs, SMB lateral movement, and
/// EternalBlue-style exploits all benefit from this misconfiguration. We treat it as
/// <c>Critical</c>.
/// </para>
///
/// <para>
/// Registry path:
/// <c>HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\&lt;Profile&gt;\DefaultInboundAction</c>.
/// Same triplet of profiles as <see cref="FirewallCheck"/> (Domain / Standard / Public).
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallDefaultInboundCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public FirewallDefaultInboundCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-FW-02",
        Title: "Firewall mặc định cho phép TẤT CẢ kết nối inbound",
        DefaultSeverity: Severity.Critical,
        Category: "Tường lửa máy trạm",
        CisReference: "CIS 9.1.2 / 9.2.2 / 9.3.2");

    private const string ProfileRoot = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
        var weak = new List<string>();

        foreach (var p in profiles)
        {
            var action = _registry.GetValue(
                RegistryHive.LocalMachine,
                $@"{ProfileRoot}\{p}",
                "DefaultInboundAction") as int?;
            // Missing == Block (Windows default). Only an explicit 0 is unsafe.
            if (action == 0)
            {
                weak.Add(p);
            }
        }

        if (weak.Count == 0)
        {
            return Task.FromResult<Finding?>(null);
        }

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.Critical,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: "DefaultInboundAction=0 (Allow) trên profile: " + string.Join(", ", weak),
            remediation: "Đặt mặc định Block cho inbound trên cả 3 profile. "
                         + "Lệnh: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound. "
                         + "Hoặc PowerShell: Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block."));
    }
}
