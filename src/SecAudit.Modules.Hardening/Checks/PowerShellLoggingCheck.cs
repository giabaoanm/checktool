using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

[SupportedOSPlatform("windows")]
public sealed class PowerShellLoggingCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public PowerShellLoggingCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-PS-LOG-01",
        Title: "PowerShell script-block / module logging is not enabled",
        DefaultSeverity: Severity.Medium,
        Category: "Logging & Audit",
        CisReference: "CIS 18.9.100.1 / 18.9.100.2");

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        // Machine policy path. If undefined, PS does not log script blocks.
        var scriptBlock = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging") as int? ?? 0;

        var moduleLog = _registry.GetValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
            "EnableModuleLogging") as int? ?? 0;

        if (scriptBlock == 1 && moduleLog == 1)
        {
            return Task.FromResult<Finding?>(null);
        }

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.Medium,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: $"EnableScriptBlockLogging={scriptBlock}, EnableModuleLogging={moduleLog}",
            remediation: "Via GPO: Administrative Templates → Windows Components → Windows PowerShell. "
                         + "Enable 'Turn on PowerShell Script Block Logging' and 'Turn on Module Logging' (log to * modules). "
                         + "Adds visibility for post-exploitation LOLBin activity."));
    }
}
