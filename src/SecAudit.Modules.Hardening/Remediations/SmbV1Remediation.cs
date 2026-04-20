using System.Runtime.Versioning;
using SecAudit.Infrastructure.Process;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Removes SMB1 from the OS — counterpart to HD-SMB1-01.
/// Strategy:
///   1. Disable the SMB1 server-side via PowerShell <c>Set-SmbServerConfiguration -EnableSMB1Protocol $false</c>.
///   2. Disable the optional feature so the binaries are removed on next boot:
///      <c>Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart</c>.
/// Step 2 requires reboot to fully detach the driver. Step 1 takes effect immediately
/// for new connections. We wrap both in a single PowerShell call to keep elevation hops minimal.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SmbV1Remediation : IRemediationAction
{
    private readonly IProcessRunner _runner;
    public SmbV1Remediation(IProcessRunner runner) => _runner = runner;

    public string FindingId => "HD-SMB1-01";
    public string Title => "Vô hiệu hoá giao thức SMBv1";
    public string Description =>
        "Tắt SMB1 server (Set-SmbServerConfiguration) và gỡ tính năng SMB1Protocol "
        + "(Disable-WindowsOptionalFeature). Loại bỏ bề mặt tấn công EternalBlue / WannaCry. "
        + "Cần khởi động lại máy để gỡ hoàn toàn driver mrxsmb10.";
    public bool RequiresReboot => true;
    public bool RequiresAdmin => true;

    public async Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        // -NoProfile speeds startup; -ExecutionPolicy Bypass guards against locked-down policy.
        // The two cmdlets are chained with `;` so a server-config failure doesn't block the feature removal.
        const string script =
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false; "
            + "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop";
        try
        {
            var result = await _runner.RunAsync(
                "powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
                TimeSpan.FromMinutes(2),
                cancellationToken).ConfigureAwait(false);

            if (result.ExitCode == 0)
            {
                return new RemediationResult(
                    Succeeded: true,
                    Message: "Đã tắt SMB1 và gỡ tính năng SMB1Protocol. Cần khởi động lại để gỡ driver.",
                    RebootRequired: true);
            }

            return new RemediationResult(
                Succeeded: false,
                Message: $"PowerShell trả về mã {result.ExitCode}. stderr: {result.StandardError.Trim()}",
                RebootRequired: false);
        }
        catch (Exception ex)
        {
            return new RemediationResult(
                Succeeded: false,
                Message: $"Lỗi khi gọi PowerShell: {ex.Message}",
                RebootRequired: false);
        }
    }
}
