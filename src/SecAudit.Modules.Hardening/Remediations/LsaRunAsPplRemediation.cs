using System.Runtime.Versioning;
using SecAudit.Infrastructure.Registry;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening.Remediations;

/// <summary>
/// Enables LSASS protection (RunAsPPL=1) — counterpart to HD-LSA-PPL-01.
/// Requires reboot. Mode 1 = standard PPL; Microsoft also documents mode 2 (UEFI lock)
/// but we pick 1 because removing it later requires a special UEFI variable wipe.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LsaRunAsPplRemediation : IRemediationAction
{
    private const string KeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private readonly IRegistryWriter _writer;

    public LsaRunAsPplRemediation(IRegistryWriter writer) => _writer = writer;

    public string FindingId => "HD-LSA-PPL-01";
    public string Title => "Bật bảo vệ LSASS (RunAsPPL)";
    public string Description =>
        @"Đặt HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD). "
        + "Sau khi khởi động lại, LSASS chạy ở chế độ Protected Process Light, "
        + "chống các công cụ dump credential (Mimikatz, ProcDump...). "
        + "Cần khởi động lại máy để có hiệu lực.";
    public bool RequiresReboot => true;
    public bool RequiresAdmin => true;

    public Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            _writer.SetValue(RegistryHive.LocalMachine, KeyPath, "RunAsPPL",
                1, RegistryValueKind.DWord);
            return Task.FromResult(new RemediationResult(
                Succeeded: true,
                Message: "Đã đặt RunAsPPL=1. Cần khởi động lại để có hiệu lực.",
                RebootRequired: true));
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
