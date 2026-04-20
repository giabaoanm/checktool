using System.Runtime.Versioning;
using SecAudit.Infrastructure.Process;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Disables the built-in Guest account — counterpart to HD-ACCT-GUEST-01.
/// Uses <c>net user Guest /active:no</c>; on localized Windows the account is still
/// addressable by RID (Guest = SID -501) so the literal name works because Microsoft
/// keeps "Guest" as the canonical name even on localized SKUs.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GuestAccountRemediation : IRemediationAction
{
    private readonly IProcessRunner _runner;
    public GuestAccountRemediation(IProcessRunner runner) => _runner = runner;

    public string FindingId => "HD-ACCT-GUEST-01";
    public string Title => "Vô hiệu hoá tài khoản Guest";
    public string Description =>
        "Chạy `net user Guest /active:no` để tắt tài khoản khách. "
        + "Ngăn truy cập SMB / RDP ẩn danh khi cấu hình share lỏng lẻo.";
    public bool RequiresReboot => false;
    public bool RequiresAdmin => true;

    public async Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _runner.RunAsync(
                "net.exe",
                "user Guest /active:no",
                TimeSpan.FromSeconds(10),
                cancellationToken).ConfigureAwait(false);

            if (result.ExitCode == 0)
            {
                return new RemediationResult(
                    Succeeded: true,
                    Message: "Đã vô hiệu hoá tài khoản Guest.",
                    RebootRequired: false);
            }

            return new RemediationResult(
                Succeeded: false,
                Message: $"net.exe trả về mã {result.ExitCode}. stderr: {result.StandardError.Trim()}",
                RebootRequired: false);
        }
        catch (Exception ex)
        {
            return new RemediationResult(
                Succeeded: false,
                Message: $"Lỗi khi gọi net.exe: {ex.Message}",
                RebootRequired: false);
        }
    }
}
