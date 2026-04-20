using System.Runtime.Versioning;
using SecAudit.Infrastructure.Registry;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Disables AutoRun/AutoPlay on all drive types — counterpart to
/// <see cref="Checks.AutoRunCheck"/> (HD-AUTORUN-01).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AutoRunRemediation : IRemediationAction
{
    private const string KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private readonly IRegistryWriter _writer;

    public AutoRunRemediation(IRegistryWriter writer) => _writer = writer;

    public string FindingId => "HD-AUTORUN-01";
    public string Title => "Tắt AutoRun/AutoPlay cho mọi loại ổ đĩa";
    public string Description =>
        @"Đặt HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer "
        + "NoDriveTypeAutoRun = 0xFF và NoAutorun = 1. "
        + "Ngăn USB / CD-ROM tự chạy lệnh khi cắm vào.";
    public bool RequiresReboot => false;
    public bool RequiresAdmin => true;

    public Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            _writer.SetValue(RegistryHive.LocalMachine, KeyPath, "NoDriveTypeAutoRun",
                0xFF, RegistryValueKind.DWord);
            _writer.SetValue(RegistryHive.LocalMachine, KeyPath, "NoAutorun",
                1, RegistryValueKind.DWord);
            return Task.FromResult(new RemediationResult(
                Succeeded: true,
                Message: "Đã đặt NoDriveTypeAutoRun=0xFF và NoAutorun=1.",
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
