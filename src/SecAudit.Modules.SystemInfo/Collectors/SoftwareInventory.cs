using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.SystemInfo.Models;

namespace SecAudit.Modules.SystemInfo.Collectors;

/// <summary>
/// Enumerates installed software from the Uninstall registry keys.
/// Deliberately does NOT use WMI Win32_Product — that class triggers MSI self-repair
/// on every enumerated package and generates 1033 events in the Application log.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SoftwareInventory
{
    private readonly IRegistryReader _registry;
    private readonly ILogger<SoftwareInventory> _logger;

    public SoftwareInventory(IRegistryReader registry, ILogger<SoftwareInventory> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    private const string HklmUninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string HklmUninstallWow = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string HkcuUninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public IReadOnlyList<InstalledSoftware> Collect()
    {
        var results = new List<InstalledSoftware>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Harvest(RegistryHive.LocalMachine, HklmUninstall, view64: true, "HKLM:64", results, seen);
        Harvest(RegistryHive.LocalMachine, HklmUninstallWow, view64: true, "HKLM:WOW6432", results, seen);
        Harvest(RegistryHive.CurrentUser, HkcuUninstall, view64: true, "HKCU", results, seen);

        results.Sort((a, b) =>
            string.Compare(a.DisplayName, b.DisplayName, StringComparison.OrdinalIgnoreCase));
        return results;
    }

    private void Harvest(
        RegistryHive hive,
        string root,
        bool view64,
        string sourceLabel,
        List<InstalledSoftware> sink,
        HashSet<string> seen)
    {
        IReadOnlyList<string> children;
        try
        {
            children = _registry.GetSubKeyNames(hive, root, view64);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Enumerate uninstall root failed: {Root}", root);
            return;
        }

        foreach (var child in children)
        {
            var subKey = root + "\\" + child;
            try
            {
                var displayName = _registry.GetValue(hive, subKey, "DisplayName", view64)?.ToString();
                if (string.IsNullOrWhiteSpace(displayName))
                {
                    continue;
                }

                // Skip Windows Update / hotfix entries — they belong to the patch module,
                // not the general software inventory (they add noise here).
                var systemComponent = _registry.GetValue(hive, subKey, "SystemComponent", view64);
                if (systemComponent is int sc && sc == 1)
                {
                    continue;
                }
                var parent = _registry.GetValue(hive, subKey, "ParentKeyName", view64)?.ToString();
                if (!string.IsNullOrEmpty(parent))
                {
                    continue;
                }

                var version = _registry.GetValue(hive, subKey, "DisplayVersion", view64)?.ToString();
                var publisher = _registry.GetValue(hive, subKey, "Publisher", view64)?.ToString();
                var installDate = _registry.GetValue(hive, subKey, "InstallDate", view64)?.ToString();
                var installLocation = _registry.GetValue(hive, subKey, "InstallLocation", view64)?.ToString();

                // Dedup key: name + version (an app can appear under HKLM:64 and HKLM:WOW6432 both).
                var dedup = (displayName + "|" + (version ?? "")).Trim();
                if (!seen.Add(dedup))
                {
                    continue;
                }

                sink.Add(new InstalledSoftware(
                    DisplayName: displayName.Trim(),
                    Version: version,
                    Publisher: publisher,
                    InstallDate: installDate,
                    InstallLocation: installLocation,
                    Source: sourceLabel));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Read uninstall entry failed: {SubKey}", subKey);
            }
        }
    }
}
