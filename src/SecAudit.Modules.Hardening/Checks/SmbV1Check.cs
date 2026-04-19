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

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        // Client side: mrxsmb10 service Start value. Missing key = feature not installed (safe).
        // 4 = Disabled (safe). 1/2/3 = Enabled (unsafe).
        var clientServiceExists = _registry.GetSubKeyNames(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services").Any(n => string.Equals(n, "mrxsmb10", StringComparison.OrdinalIgnoreCase));
        var clientStart = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\mrxsmb10",
            "Start") as int?;
        var clientEnabled = clientServiceExists && clientStart is not null && clientStart != 4;

        // Server side: LanmanServer\Parameters\SMB1. Explicit 1 = Enabled. Missing on Win10 1709+ = disabled.
        var serverSmb1 = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1") as int?;
        var serverEnabled = serverSmb1 == 1;

        if (!clientEnabled && !serverEnabled)
        {
            return Task.FromResult<Finding?>(null);
        }

        var clientDesc = !clientServiceExists
            ? "mrxsmb10 service not installed"
            : $"mrxsmb10.Start={clientStart?.ToString() ?? "(missing)"}";
        var serverDesc = $"LanmanServer.SMB1={serverSmb1?.ToString() ?? "(missing)"}";
        var evidence = $"{clientDesc}, {serverDesc}";
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
