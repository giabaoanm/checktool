using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class RdpNlaCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public RdpNlaCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-RDP-01",
        Title: "Remote Desktop đang bật nhưng không yêu cầu NLA",
        DefaultSeverity: Severity.High,
        Category: "Truy cập từ xa",
        CisReference: "CIS 2.3.7.2 / 18.9.65.3.9.x");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        // fDenyTSConnections: 1 = RDP disabled (safe), 0 = RDP enabled.
        var deny = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections") as int? ?? 1;

        if (deny == 1)
        {
            return Task.FromResult<Finding?>(null); // RDP off → nothing to warn about.
        }

        var nla = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication") as int? ?? 0;

        if (nla == 1)
        {
            return Task.FromResult<Finding?>(null); // RDP on with NLA → OK.
        }

        var evidence = $"fDenyTSConnections={deny} (RDP đang bật), UserAuthentication={nla} (NLA đang tắt)";
        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.High,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: evidence,
            remediation: "Nếu cần dùng RDP, bật NLA: System Properties → Remote → chọn 'Allow connections only from computers running Remote Desktop with NLA'. "
                         + "Nếu không dùng thì tắt hẳn RDP."));
    }
}
