using System.Runtime.Versioning;
using SecAudit.Infrastructure.Registry;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Enables PowerShell ScriptBlock + Module logging — counterpart to HD-PS-LOG-01.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PowerShellLoggingRemediation : IRemediationAction
{
    private const string ScriptBlockKey =
        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
    private const string ModuleLoggingKey =
        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";
    private const string ModuleNamesKey =
        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames";

    private readonly IRegistryWriter _writer;
    public PowerShellLoggingRemediation(IRegistryWriter writer) => _writer = writer;

    public string FindingId => "HD-PS-LOG-01";
    public string Title => "Bật ghi log PowerShell (ScriptBlock + Module)";
    public string Description =>
        "Bật EnableScriptBlockLogging=1 và EnableModuleLogging=1, ghi log cho mọi module (*). "
        + "Tăng khả năng phát hiện mã PowerShell độc hại (LOLBin) trong Event Viewer "
        + "(kênh Microsoft-Windows-PowerShell/Operational, EID 4104).";
    public bool RequiresReboot => false;
    public bool RequiresAdmin => true;

    public Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            _writer.SetValue(RegistryHive.LocalMachine, ScriptBlockKey,
                "EnableScriptBlockLogging", 1, RegistryValueKind.DWord);
            _writer.SetValue(RegistryHive.LocalMachine, ModuleLoggingKey,
                "EnableModuleLogging", 1, RegistryValueKind.DWord);
            // Log all modules — empty value name with "*" is the documented convention.
            _writer.SetValue(RegistryHive.LocalMachine, ModuleNamesKey,
                "*", "*", RegistryValueKind.String);
            return Task.FromResult(new RemediationResult(
                Succeeded: true,
                Message: "Đã bật ScriptBlock + Module logging cho mọi module.",
                RebootRequired: false));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new RemediationResult(
                Succeeded: false,
                Message: $"Lỗi khi ghi registry: {ex.Message}",
                RebootRequired: false));
        }
    }
}
