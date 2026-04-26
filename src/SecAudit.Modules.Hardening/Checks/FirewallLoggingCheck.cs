using System.Globalization;
using System.Runtime.Versioning;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Verifies that the Windows Firewall is logging dropped packets and that the log file
/// is sized appropriately for forensics.
///
/// <para>
/// Stock Windows ships with firewall logging <b>disabled</b>. That's fine for a desktop
/// workstation, but a SOC-managed endpoint should at minimum capture dropped packets so
/// post-incident triage can answer "what tried to talk to this box at 03:14?" without
/// having to install Sysmon or stand up a full event collector.
/// </para>
///
/// <para>
/// Per CIS sub-rule 9.x.5/9.x.6 we look at, on every profile:
/// <list type="bullet">
///   <item><c>LogDroppedPackets = 1</c> — must be on (dropped traffic is the forensic gold).</item>
///   <item><c>LogFileSize</c> ≥ 16384 (KB) — Microsoft's recommended floor; the default 4096 fills in minutes on a noisy network.</item>
/// </list>
/// We do NOT require <c>LogSuccessfulConnections=1</c> — it's noisy and almost never useful
/// for SMB endpoints; turning it on without log shipping is just self-DoS on disk.
/// </para>
///
/// <para>
/// Severity is <c>Medium</c>: the box is not actively unsafe, just blind during incident
/// response. Multiple profile failures collapse into a single finding row.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallLoggingCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public FirewallLoggingCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-FW-04",
        Title: "Firewall logging chưa bật hoặc dung lượng log quá nhỏ",
        DefaultSeverity: Severity.Medium,
        Category: "Tường lửa máy trạm",
        CisReference: "CIS 9.1.5 / 9.2.5 / 9.3.5");

    private const string ProfileRoot =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    private const int RecommendedMinLogSizeKb = 16384;

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
        var problems = new List<string>();

        foreach (var p in profiles)
        {
            var keyPath = $@"{ProfileRoot}\{p}\Logging";
            var dropped = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "LogDroppedPackets") as int?;
            var sizeKb = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "LogFileSize") as int?;

            // Default install: LogDroppedPackets is missing/0. We treat both as "off".
            var loggingOff = dropped is null or 0;
            // Default LogFileSize on a fresh install is 4096 KB. Only flag if the value is
            // definitively below the recommended minimum (a missing value also counts as
            // "default" and therefore too small).
            var sizeTooSmall = sizeKb is null || sizeKb < RecommendedMinLogSizeKb;

            if (loggingOff)
            {
                problems.Add($"{p}: LogDroppedPackets={(dropped?.ToString(CultureInfo.InvariantCulture) ?? "(không có)")}");
            }
            else if (sizeTooSmall)
            {
                // Only flag size when logging itself is on — otherwise size is moot.
                problems.Add($"{p}: LogFileSize={(sizeKb?.ToString(CultureInfo.InvariantCulture) ?? "(default 4096)")} KB (nên ≥ {RecommendedMinLogSizeKb})");
            }
        }

        if (problems.Count == 0)
        {
            return Task.FromResult<Finding?>(null);
        }

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: Severity.Medium,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: string.Join("; ", problems),
            remediation: "Bật log dropped packets và nâng dung lượng log lên 16 MB cho cả 3 profile. "
                         + "PowerShell mẫu (chạy với quyền admin):\n"
                         + "Set-NetFirewallProfile -Profile Domain,Public,Private "
                         + "-LogBlocked True -LogMaxSizeKilobytes 16384 "
                         + "-LogFileName %systemroot%\\System32\\LogFiles\\Firewall\\pfirewall.log"));
    }
}
