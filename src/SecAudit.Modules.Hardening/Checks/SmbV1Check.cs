using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class SmbV1Check : ICheck
{
    private readonly IRegistryReader _registry;
    public SmbV1Check(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-SMB1-01",
        Title: "SMBv1 protocol is enabled",
        DefaultSeverity: Severity.High,
        Category: "Network Protocols",
        CisReference: "CIS 18.3.3");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken _)
    {
        // Client side: mrxsmb10 service Start value. 4 = Disabled.
        var clientStart = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\mrxsmb10",
            "Start") as int?;

        // Server side: LanmanServer\Parameters\SMB1. 0 = Disabled; absent = default-enabled on old OS.
        var serverSmb1 = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1") as int?;

        var clientEnabled = clientStart is null || clientStart != 4;
        var serverEnabled = serverSmb1 is null || serverSmb1 != 0;

        if (!clientEnabled && !serverEnabled)
        {
            return Task.FromResult<Finding?>(null);
        }

        var evidence = $"mrxsmb10.Start={clientStart?.ToString() ?? "(missing)"}, LanmanServer.SMB1={serverSmb1?.ToString() ?? "(missing)"}";
        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.High,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: evidence,
            remediation: "Disable SMBv1 via Optional Features or: "
                         + "Set-SmbServerConfiguration -EnableSMB1Protocol $false; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. "
                         + "SMBv1 is used by WannaCry/EternalBlue and has been default-off since Windows 10 1709."));
    }
}
