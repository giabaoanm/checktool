using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Globalization;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Infrastructure.Registry;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.PatchCve;

/// <summary>
/// Enumerates installed Windows hotfixes.
///
/// Live mode: WMI <c>Win32_QuickFixEngineering</c> (what <c>Get-HotFix</c> wraps). Fast and
/// covers all classic updates.
///
/// Offline mode (WinPE / mounted volume): WMI is unavailable for the target volume, so we
/// read the Component Based Servicing packages hive at
/// <c>SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages</c>.
/// CBS package names embed the KB number; we extract it with a regex. This is how Microsoft's
/// own <c>DISM /get-packages</c> works offline and catches the same set of KBs as
/// <c>Get-HotFix</c> plus servicing-stack increments.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class HotfixInventory
{
    private readonly IWmiQuery _wmi;
    private readonly IRegistryReader _registry;
    private readonly IOfflineTarget _target;
    private readonly ILogger<HotfixInventory> _logger;

    public HotfixInventory(
        IWmiQuery wmi,
        IRegistryReader registry,
        IOfflineTarget target,
        ILogger<HotfixInventory> logger)
    {
        _wmi = wmi;
        _registry = registry;
        _target = target;
        _logger = logger;
    }

    public IReadOnlySet<string> CollectInstalledKbs()
    {
        return CollectInstalledUpdates()
            .Select(update => update.KbId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<InstalledKb> CollectInstalledUpdates()
    {
        return _target.IsLive ? CollectLive() : CollectOffline();
    }

    private List<InstalledKb> CollectLive()
    {
        var updates = new List<InstalledKb>();
        try
        {
            var rows = _wmi.Query(@"\\.\ROOT\CIMV2",
                "SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering");
            foreach (var row in rows)
            {
                if (row.TryGetValue("HotFixID", out var v) && v?.ToString() is { Length: > 0 } kb)
                {
                    updates.Add(new InstalledKb(
                        KbId: kb.Trim(),
                        InstalledOn: TryParseInstalledOn(row.TryGetValue("InstalledOn", out var installedOn)
                            ? installedOn?.ToString()
                            : null),
                        Description: row.TryGetValue("Description", out var description)
                            ? description?.ToString()
                            : null,
                        Source: "Win32_QuickFixEngineering"));
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Win32_QuickFixEngineering query failed");
        }
        return updates
            .GroupBy(update => update.KbId, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(update => update.InstalledOn).First())
            .ToList();
    }

    private List<InstalledKb> CollectOffline()
    {
        var updates = new Dictionary<string, InstalledKb>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // CBS packages registry layout (offline):
            //   SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages
            //     Package_1_for_KB4577266~31bf3856ad364e35~amd64~~10.0.1.1
            //     Package_for_KB5034441~31bf3856ad364e35~amd64~~22621.1.1.0
            //     ...
            // Each subkey whose name embeds KB<number> is considered installed if its
            // "CurrentState" DWORD is 0x70 (Installed) or 0x50 (Superseded but still present).
            var subs = _registry.GetSubKeyNames(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");
            foreach (var pkg in subs)
            {
                var match = KbPattern().Match(pkg);
                if (!match.Success) { continue; }
                var kb = "KB" + match.Groups[1].Value;

                var state = _registry.GetValue(RegistryHive.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\" + pkg,
                    "CurrentState") as int?;
                if (state is 0x70 or 0x50 or 0x90 or 0x00) // Installed, Superseded, Staged, or unknown-but-present
                {
                    updates[kb] = new InstalledKb(
                        KbId: kb,
                        InstalledOn: null,
                        Description: "CBS package",
                        Source: "CBS offline package registry");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CBS packages enumeration failed (offline)");
        }
        return updates.Values.ToList();
    }

    private static DateTimeOffset? TryParseInstalledOn(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out var dto)
            || DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dto))
        {
            return dto;
        }

        if (DateTime.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out var dt)
            || DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dt))
        {
            return new DateTimeOffset(dt);
        }

        return null;
    }

    // Matches "KB" followed by 6-8 digits anywhere in the package name.
    [GeneratedRegex(@"KB(\d{6,8})", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex KbPattern();
}

public sealed record InstalledKb(
    string KbId,
    DateTimeOffset? InstalledOn,
    string? Description,
    string Source);
