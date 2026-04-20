using System.Runtime.Versioning;
using SecAudit.Infrastructure.Process;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Enables the Windows Defender Firewall on all three profiles
/// (Domain / Private / Public) — counterpart to HD-FW-01.
/// Uses <c>netsh advfirewall</c> rather than direct registry writes so the
/// Windows Firewall service notices the change immediately (no service restart needed).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallRemediation : IRemediationAction
{
    private readonly IProcessRunner _runner;
    public FirewallRemediation(IProcessRunner runner) => _runner = runner;

    public string FindingId => "HD-FW-01";
    public string Title => "Bật Windows Defender Firewall trên mọi profile";
    public string Description =>
        "Chạy `netsh advfirewall set allprofiles state on` để bật firewall cho cả 3 profile "
        + "Domain / Private / Public. Có hiệu lực ngay, không cần khởi động lại.";
    public bool RequiresReboot => false;
    public bool RequiresAdmin => true;

    public async Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _runner.RunAsync(
                "netsh.exe",
                "advfirewall set allprofiles state on",
                TimeSpan.FromSeconds(10),
                cancellationToken).ConfigureAwait(false);

            if (result.ExitCode == 0)
            {
                return new RemediationResult(
                    Succeeded: true,
                    Message: "Đã bật firewall cho cả 3 profile (Domain/Private/Public).",
                    RebootRequired: false);
            }

            return new RemediationResult(
                Succeeded: false,
                Message: $"netsh trả về mã {result.ExitCode}. stderr: {result.StandardError.Trim()}",
                RebootRequired: false);
        }
        catch (Exception ex)
        {
            return new RemediationResult(
                Succeeded: false,
                Message: $"Lỗi khi gọi netsh: {ex.Message}",
                RebootRequired: false);
        }
    }
}
