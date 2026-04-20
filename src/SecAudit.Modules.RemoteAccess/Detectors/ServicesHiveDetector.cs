using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.RemoteAccess.Detectors;

/// <summary>
/// Enumerates the Services hive (<c>HKLM\SYSTEM\CurrentControlSet\Services</c>) and flags
/// auto-start services whose <c>ImagePath</c> points into user-writable folders (Temp,
/// AppData, ProgramData root, Public) or invokes a LOLBin/encoded PowerShell. This is
/// MITRE T1543.003 — "Create or Modify System Process: Windows Service".
///
/// Works identically in live and offline modes via <see cref="IRegistryReader"/>.
///
/// Offline caveat: the offline hive stores <c>HKLM\SYSTEM\ControlSet001\...</c> rather than
/// <c>CurrentControlSet</c> (which is a symbolic link created at runtime). We try both.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServicesHiveDetector
{
    public sealed record SuspiciousService(string Name, string ImagePath, string Start, string Reason);

    private static readonly string[] SuspiciousFragments =
    {
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\users\public\",
        @"\windows\temp\",
        @"\programdata\",      // root of ProgramData — legitimate services live in a subfolder
        "powershell.exe -enc ",
        "powershell -enc ",
        "-encodedcommand",
        "rundll32.exe javascript:",
        "regsvr32 /s /u /i:http"
    };

    private static readonly string[] ServicesRoots =
    {
        @"SYSTEM\CurrentControlSet\Services",
        @"SYSTEM\ControlSet001\Services" // Offline: CurrentControlSet is a live-only symlink.
    };

    private readonly IRegistryReader _registry;
    private readonly ILogger<ServicesHiveDetector> _logger;

    public ServicesHiveDetector(IRegistryReader registry, ILogger<ServicesHiveDetector> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    public IReadOnlyList<SuspiciousService> Detect()
    {
        var hits = new List<SuspiciousService>();
        var seenRoot = false;
        foreach (var root in ServicesRoots)
        {
            var names = _registry.GetSubKeyNames(RegistryHive.LocalMachine, root);
            if (names.Count == 0) { continue; }
            seenRoot = true;
            foreach (var svc in names)
            {
                try
                {
                    var imagePath = _registry.GetValue(RegistryHive.LocalMachine,
                        $"{root}\\{svc}", "ImagePath") as string;
                    if (string.IsNullOrEmpty(imagePath)) { continue; }
                    var startVal = _registry.GetValue(RegistryHive.LocalMachine,
                        $"{root}\\{svc}", "Start");
                    // Only Auto (2) or Boot (0) / System (1) start are interesting for persistence.
                    var startInt = startVal is int i ? i : -1;
                    if (startInt > 3 || startInt < 0) { continue; }
                    var lower = imagePath.ToLowerInvariant();
                    foreach (var frag in SuspiciousFragments)
                    {
                        if (lower.Contains(frag, StringComparison.Ordinal))
                        {
                            hits.Add(new SuspiciousService(svc, imagePath,
                                StartToText(startInt),
                                $"ImagePath contains '{frag.Trim()}'"));
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Service read failed: {Service}", svc);
                }
            }
            // Once we've found any services root that yielded entries, don't double-count from the other.
            break;
        }
        if (!seenRoot)
        {
            _logger.LogDebug("No services root readable (both CurrentControlSet and ControlSet001 empty).");
        }
        return hits;
    }

    private static string StartToText(int s) => s switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => s.ToString()
    };
}
