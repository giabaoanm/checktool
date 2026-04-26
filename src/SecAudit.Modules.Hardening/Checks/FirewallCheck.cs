using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class FirewallCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public FirewallCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-FW-01",
        Title: "Windows Firewall bị tắt trên một hoặc nhiều profile",
        DefaultSeverity: Severity.High,
        Category: "Tường lửa máy trạm",
        CisReference: "CIS 9.1 / 9.2 / 9.3");

    private const string ProfileRoot = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
        var disabled = new List<string>();

        foreach (var p in profiles)
        {
            var enabled = _registry.GetValue(
                RegistryHive.LocalMachine,
                $@"{ProfileRoot}\{p}",
                "EnableFirewall") as int?;
            // Default behaviour on modern Windows when value is absent is ENABLED.
            if (enabled == 0)
            {
                disabled.Add(p);
            }
        }

        if (disabled.Count == 0)
        {
            return Task.FromResult<Finding?>(null);
        }

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.High,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: "EnableFirewall=0 trên profile: " + string.Join(", ", disabled),
            remediation: "Bật Windows Defender Firewall cho cả 3 profile (Domain, Private, Public). "
                         + "Lệnh: netsh advfirewall set allprofiles state on"));
    }
}
