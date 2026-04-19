using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class UacCheck : ICheck
{
    private const string Key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private readonly IRegistryReader _registry;

    public UacCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-UAC-01",
        Title: "User Account Control (UAC) is disabled",
        DefaultSeverity: Severity.High,
        Category: "Accounts & UAC",
        CisReference: "CIS 2.3.17.x");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var enableLua = _registry.GetValue(RegistryHive.LocalMachine, Key, "EnableLUA") as int? ?? 1;
        var consent = _registry.GetValue(RegistryHive.LocalMachine, Key, "ConsentPromptBehaviorAdmin") as int? ?? 5;
        var secureDesktop = _registry.GetValue(RegistryHive.LocalMachine, Key, "PromptOnSecureDesktop") as int? ?? 1;

        if (enableLua == 1 && consent != 0 && secureDesktop == 1)
        {
            return Task.FromResult<Finding?>(null);
        }

        var evidence = $"EnableLUA={enableLua}, ConsentPromptBehaviorAdmin={consent}, PromptOnSecureDesktop={secureDesktop}";
        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: enableLua == 0 ? Severity.High : Severity.Medium,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: evidence,
            remediation: "Set EnableLUA=1, ConsentPromptBehaviorAdmin=2 (prompt on secure desktop), PromptOnSecureDesktop=1."));
    }
}
