using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.SystemInfo.Models;

namespace SecAudit.Modules.SystemInfo.Collectors;

/// <summary>
/// Heuristic detector for common "KMSpico / AutoKMS" style Office activation cracks.
/// Signals collected independently — finding fires if any one triggers. Each signal is evidence-only
/// (false positives possible, e.g., legitimate KMS host on loopback). Output is a list of matched
/// evidence lines so an admin can verify.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OfficeKmsPicoDetector
{
    private readonly IRegistryReader _registry;
    private readonly ILogger<OfficeKmsPicoDetector> _logger;

    public OfficeKmsPicoDetector(IRegistryReader registry, ILogger<OfficeKmsPicoDetector> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    private static readonly string[] SuspiciousKmsHosts =
    {
        "127.0.0.2",
        "kms.digiboy.ir",
        "kms.MSGuides.com",
        "s8.uk.to",
        "kms.03k.org",
        "kms.xspace.in"
    };

    private static readonly string[] KmsToolFilenames =
    {
        "kmspico.exe",
        "kmseldi.exe",
        "kmsauto.exe",
        "kmsautonet.exe",
        "kmsautolite.exe",
        "autopico.exe",
        "servicekms.exe",
        "activator.exe",
        "hwidgen.exe"
    };

    public (bool Suspected, IReadOnlyList<string> Evidence) Detect(
        IReadOnlyList<LicenseInfo> officeLicenses)
    {
        var evidence = new List<string>();

        // Signal 1: Office product is licensed via KMS and points at a suspicious host.
        foreach (var lic in officeLicenses)
        {
            var desc = lic.Description ?? string.Empty;
            var isVolumeKms =
                desc.Contains("KMS", StringComparison.OrdinalIgnoreCase)
                || desc.Contains("VOLUME", StringComparison.OrdinalIgnoreCase);

            if (!string.IsNullOrEmpty(lic.KmsServer))
            {
                foreach (var bad in SuspiciousKmsHosts)
                {
                    if (lic.KmsServer.Contains(bad, StringComparison.OrdinalIgnoreCase))
                    {
                        evidence.Add($"Office license '{lic.Product}' points at known-bad KMS host: {lic.KmsServer}");
                        break;
                    }
                }
            }

            if (isVolumeKms && lic.KmsServer is not null &&
                (lic.KmsServer.StartsWith("127.", StringComparison.Ordinal)
                 || lic.KmsServer.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
            {
                evidence.Add($"Office license '{lic.Product}' activated via loopback KMS ({lic.KmsServer}) — typical KMSpico signature");
            }
        }

        // Signal 2: KMSpico-style files on disk (common install locations).
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("WINDIR") + @"\System32",
            Environment.GetEnvironmentVariable("WINDIR") + @"\AutoKMS"
        };
        foreach (var root in roots.Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r)))
        {
            foreach (var fn in KmsToolFilenames)
            {
                try
                {
                    var matches = Directory.EnumerateFiles(root, fn, SearchOption.TopDirectoryOnly).Take(1);
                    foreach (var hit in matches)
                    {
                        evidence.Add($"KMS-tool style binary present: {hit}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "File search failed for {Root}\\{File}", root, fn);
                }
            }
        }

        // Signal 3: scheduled task name "AutoPico" (common KMSpico persistence entry).
        try
        {
            var taskNames = _registry.GetSubKeyNames(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
            foreach (var t in taskNames)
            {
                if (t.Contains("AutoPico", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("AutoKMS", StringComparison.OrdinalIgnoreCase))
                {
                    evidence.Add($"Scheduled task found: {t} — typical KMSpico/AutoKMS persistence");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Scheduled task registry enumeration failed");
        }

        return (evidence.Count > 0, evidence);
    }
}
