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
        // NOTE: '\programdata\' alone was previously here but caused 5+ false positives
        // per machine at Sơn La (Microsoft Defender, NVIDIA NvContainer, Kaspersky AVP
        // all live in subfolders of ProgramData and are signed legit binaries). Removed
        // and replaced with an allowlist below — services whose path is under a known
        // vendor sub-tree of ProgramData are NOT flagged regardless.
        "powershell.exe -enc ",
        "powershell -enc ",
        "-encodedcommand",
        "rundll32.exe javascript:",
        "regsvr32 /s /u /i:http"
    };

    /// <summary>
    /// Subfolders of <c>%ProgramData%</c> that legitimate vendors install services into.
    /// A service whose ImagePath sits under one of these is NEVER flagged regardless of
    /// what other heuristics say — these vendors are routinely audited and false-positive
    /// noise here drowns out the real signal.
    /// </summary>
    private static readonly string[] ProgramDataAllowList =
    {
        @"\programdata\microsoft\windows defender\",
        @"\programdata\microsoft\windows security health\",
        @"\programdata\microsoft\protect\",
        @"\programdata\nvidia\",
        @"\programdata\nvidia corporation\",
        @"\programdata\kaspersky lab\",
        @"\programdata\kaspersky\",
        @"\programdata\symantec\",
        @"\programdata\norton\",
        @"\programdata\eset\",
        @"\programdata\bitdefender\",
        @"\programdata\trend micro\",
        @"\programdata\amd\",
        @"\programdata\intel\",
        @"\programdata\realtek\",
        @"\programdata\package cache\",   // MS installer cache
    };

    /// <summary>
    /// True when the path is in <see cref="ProgramDataAllowList"/> — i.e. a known-legit
    /// vendor subfolder of ProgramData. Used to suppress false positives that the
    /// generic "\programdata\" rule used to fire.
    /// </summary>
    private static bool IsProgramDataAllowed(string lowerPath)
    {
        foreach (var allowed in ProgramDataAllowList)
        {
            if (lowerPath.Contains(allowed, StringComparison.Ordinal)) { return true; }
        }
        return false;
    }

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
                    // Suppress hits whose path is under a known-legit ProgramData
                    // sub-tree (Defender, NVIDIA, Kaspersky etc). Keeps the noise
                    // floor low so real malware drops in %TEMP% / %APPDATA% stand out.
                    if (IsProgramDataAllowed(lower)) { continue; }
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
