using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.RemoteAccess.Detectors;

/// <summary>
/// Lists Run / RunOnce autostart entries from HKLM and HKCU and flags any whose target
/// path lives in a user-writable location (Temp, AppData\Local, AppData\Roaming,
/// Public folder, Downloads). Those are the locations where commodity malware drops
/// payload + persistence in one shot, so a high-confidence finding warrants follow-up.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PersistenceDetector
{
    public sealed record AutostartEntry(string Hive, string Location, string Name, string Command, bool Suspicious, string? Reason);

    private static readonly string[] RunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    };

    private static readonly string[] SuspiciousFolders =
    {
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\appdata\local\",   // local cache of legit apps too — keep medium severity
        @"\users\public\",
        @"\windows\temp\",
        @"\downloads\",
        @"\programdata\"
    };

    private readonly IRegistryReader _registry;
    private readonly ILogger<PersistenceDetector> _logger;

    public PersistenceDetector(IRegistryReader registry, ILogger<PersistenceDetector> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    public IReadOnlyList<AutostartEntry> Detect()
    {
        var results = new List<AutostartEntry>();
        foreach (var key in RunKeys)
        {
            EnumerateHive(RegistryHive.LocalMachine, key, "HKLM", results);
        }
        // HKCU equivalents (no WOW64 split for HKCU autorun)
        EnumerateHive(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU", results);
        EnumerateHive(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU", results);
        return results;
    }

    private void EnumerateHive(RegistryHive hive, string keyPath, string hiveLabel, List<AutostartEntry> sink)
    {
        try
        {
            var values = _registry.GetValueNames(hive, keyPath);
            foreach (var name in values)
            {
                var raw = _registry.GetValue(hive, keyPath, name) as string;
                if (string.IsNullOrEmpty(raw))
                {
                    continue;
                }
                var (suspicious, reason) = Classify(raw);
                sink.Add(new AutostartEntry(hiveLabel, keyPath, name, raw, suspicious, reason));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not enumerate {Hive}\\{Key}", hiveLabel, keyPath);
        }
    }

    private static (bool, string?) Classify(string command)
    {
        var lower = command.ToLowerInvariant();
        if (IsKnownBenignAutostartCommand(lower))
        {
            return (false, null);
        }

        foreach (var folder in SuspiciousFolders)
        {
            if (lower.Contains(folder, StringComparison.Ordinal))
            {
                return (true, $"Target path lives in user-writable folder ({folder.Trim('\\')}).");
            }
        }
        // PowerShell encoded payload — high-confidence malware indicator.
        if (lower.Contains("powershell", StringComparison.Ordinal) &&
            (lower.Contains("-enc", StringComparison.Ordinal) || lower.Contains("-encodedcommand", StringComparison.Ordinal)))
        {
            return (true, "PowerShell launched with -EncodedCommand from autostart — classic obfuscation pattern.");
        }
        // mshta / wscript / cscript launching from anywhere with http(s) URL
        if ((lower.Contains("mshta", StringComparison.Ordinal) || lower.Contains("wscript", StringComparison.Ordinal) ||
             lower.Contains("cscript", StringComparison.Ordinal)) &&
            (lower.Contains("http://", StringComparison.Ordinal) || lower.Contains("https://", StringComparison.Ordinal)))
        {
            return (true, "Script host invoking remote URL from autostart — classic LOLBin abuse pattern.");
        }
        return (false, null);
    }

    private static bool IsKnownBenignAutostartCommand(string lower)
    {
        return (lower.Contains(@"\appdata\local\microsoft\windowsapps\msteams_", StringComparison.Ordinal)
                && lower.Contains(@"\ms-teams.exe", StringComparison.Ordinal))
               || lower.Contains(@"\appdata\local\anthropicclaude\claude.exe", StringComparison.Ordinal);
    }
}
