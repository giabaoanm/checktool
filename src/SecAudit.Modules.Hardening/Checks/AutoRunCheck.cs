using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class AutoRunCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public AutoRunCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-AUTORUN-01",
        Title: "AutoRun/AutoPlay is not fully disabled for removable media",
        DefaultSeverity: Severity.Medium,
        Category: "Removable Media",
        CisReference: "CIS 18.9.8.1 / 18.9.8.2");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        // NoDriveTypeAutoRun should be 0xFF (255) to disable autorun on all drive types.
        var policy = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun") as int? ?? 0;

        // NoAutorun = 1 disables AutoRun commands from running on insert.
        var noAutorun = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoAutorun") as int? ?? 0;

        if (policy == 0xFF && noAutorun == 1)
        {
            return Task.FromResult<Finding?>(null);
        }

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.Medium,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: $"NoDriveTypeAutoRun=0x{policy:X2} (expect 0xFF), NoAutorun={noAutorun} (expect 1)",
            remediation: @"Set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer "
                         + "NoDriveTypeAutoRun=0xFF and NoAutorun=1. Prevents automatic execution from USB/optical drives."));
    }
}
