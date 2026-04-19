using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// LSA Protected Process Light: when LSASS runs as a PPL, normal processes can't
/// OpenProcess(READ) against it → Mimikatz-style credential dumps fail without a
/// kernel driver. RunAsPPL=1 (or 2 on newer builds) is the hardened setting.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LsaRunAsPplCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public LsaRunAsPplCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-LSA-PPL-01",
        Title: "LSASS is not running as a Protected Process Light (RunAsPPL)",
        DefaultSeverity: Severity.High,
        Category: "Credential Protection",
        CisReference: "CIS 18.3.7");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var val = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL") as int? ?? 0;

        if (val >= 1)
        {
            return Task.FromResult<Finding?>(null);
        }

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.High,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: $"RunAsPPL={val} (expect 1 or 2)",
            remediation: @"Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL=1 (DWORD), reboot. "
                         + "Hardens LSASS against credential-dumping tools. Windows 11 22H2+ enables this by default."));
    }
}
