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
        Title: "Chưa bật ghi log Script Block / Module của PowerShell",
        DefaultSeverity: Severity.Medium,
        Category: "Ghi log & Giám sát",
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
            remediation: "Qua GPO: Administrative Templates → Windows Components → Windows PowerShell. "
                         + "Bật 'Turn on PowerShell Script Block Logging' và 'Turn on Module Logging' (áp dụng cho tất cả module: *). "
                         + "Giúp phát hiện hành vi khai thác bằng các công cụ LOLBin sau khi bị xâm nhập."));
    }
}
