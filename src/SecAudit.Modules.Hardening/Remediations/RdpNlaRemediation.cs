using System.Runtime.Versioning;
using SecAudit.Infrastructure.Registry;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Forces NLA on the RDP listener — counterpart to HD-RDP-01.
/// We do NOT touch <c>fDenyTSConnections</c> — if user has RDP intentionally on,
/// we only require it be authenticated; if RDP is off this action is harmless.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpNlaRemediation : IRemediationAction
{
    private const string KeyPath =
        @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    // SecurityLayer 2 = SSL/TLS required (the value Windows enforces alongside NLA).
    private const string TerminalServerKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";

    private readonly IRegistryWriter _writer;
    public RdpNlaRemediation(IRegistryWriter writer) => _writer = writer;

    public string FindingId => "HD-RDP-01";
    public string Title => "Bật NLA cho Remote Desktop";
    public string Description =>
        "Đặt UserAuthentication=1 và SecurityLayer=2 trên RDP-Tcp listener. "
        + "Yêu cầu client xác thực ở tầng mạng trước khi mở session — "
        + "ngăn các tấn công pre-auth (BlueKeep CVE-2019-0708, DejaBlue...).";
    public bool RequiresReboot => false;
    public bool RequiresAdmin => true;

    public Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            _writer.SetValue(RegistryHive.LocalMachine, KeyPath, "UserAuthentication",
                1, RegistryValueKind.DWord);
            _writer.SetValue(RegistryHive.LocalMachine, KeyPath, "SecurityLayer",
                2, RegistryValueKind.DWord);
            return Task.FromResult(new RemediationResult(
                Succeeded: true,
                Message: "Đã bật UserAuthentication=1 và SecurityLayer=2.",
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
