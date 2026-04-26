using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.SystemInfo.Models;

namespace SecAudit.Modules.SystemInfo.Collectors;

/// <summary>
/// Heuristic detector for unauthorized Windows / Office activators (KMSpico, KMSAuto Net,
/// HEU KMS Activator, Microsoft Toolkit, AAct, KMS-VL-ALL, Re-Loader). Each signal is
/// independent evidence — finding fires if any one triggers — and the detector runs
/// regardless of the WMI <c>LicenseStatus</c> field.
///
/// <para>
/// The fundamental problem this solves: KMSpico activates Windows by injecting a fake
/// KMS server and standing up a renewal task. After it runs, <c>SoftwareLicensingProduct.
/// LicenseStatus = 1</c> and <c>Description</c> reads exactly like a legitimate volume-
/// licensed install. WMI alone cannot tell the difference. So we look at <i>artifacts</i>:
/// installer folders, dropped binaries, scheduled tasks, hosts file overrides, GVLK
/// product key suffixes — direct evidence that a cracker is still installed even when the
/// licensing service is happy.
/// </para>
///
/// <para>
/// We also detect "post-mortem" cracker installs — KMSpico run once then partially
/// uninstalled — because the scheduled task <c>AutoPico</c> usually survives manual
/// uninstall, and the activator key entries in <c>SoftwareLicensingService</c> persist.
/// </para>
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

    /// <summary>
    /// IPs / domains that activator tools redirect "Microsoft KMS" traffic to. Loopback
    /// + the well-known public KMS-emulator hosts (which are themselves illegal services).
    /// </summary>
    private static readonly string[] SuspiciousKmsHosts =
    {
        "127.0.0.2",
        "kms.digiboy.ir",
        "kms.MSGuides.com",
        "s8.uk.to",
        "kms.03k.org",
        "kms.xspace.in",
        "kms8.MSGuides.com",
        "kms.lotro.cc",
        "kms.loli.beer",
        "kms.chinancce.com",
        "kms.zhuxianjun.com"
    };

    /// <summary>Cracker binaries we look for in the standard install folders.</summary>
    private static readonly string[] KmsToolFilenames =
    {
        // KMSpico family
        "kmspico.exe", "kmseldi.exe", "service_kms.exe", "autopico.exe",
        // KMSAuto Net
        "kmsauto.exe", "kmsautonet.exe", "kmsautolite.exe", "kmsss.exe",
        // HEU KMS Activator
        "heu_kms_activator.exe", "heukmsactivator.exe", "heu_kms.exe",
        // Microsoft Toolkit
        "microsoft toolkit.exe", "mstoolkit.exe", "ezact.exe",
        // Re-Loader Activator
        "re-loader.exe", "reloader.exe",
        // MSAct++
        "msact.exe", "msact++.exe", "msact_plus.exe",
        // Generic activator names
        "activator.exe", "hwidgen.exe", "kmsemulator.exe", "aact.exe",
        // KMS-VL-ALL
        "kms-vl-all.cmd", "kms-vl-all-aio.cmd", "kms_vl_all.cmd"
    };

    /// <summary>Folders these tools install into by default — checked regardless of OS partition.</summary>
    private static readonly string[] KmsToolDirectoryNames =
    {
        @"\KMSpico",
        @"\KMSAuto",
        @"\KMSAuto Net",
        @"\KMSAutoLite",
        @"\HEU KMS Activator",
        @"\Microsoft Toolkit",
        @"\MSToolkit",
        @"\Re-Loader",
        @"\ReLoader",
        @"\AutoKMS",
        @"\KMS-VL-ALL",
        @"\AAct",
        @"\KMS_VL_ALL"
    };

    /// <summary>
    /// Last 5 chars of public Microsoft GVLK keys — these are not RETAIL keys and their
    /// presence in <c>PartialProductKey</c> is direct evidence the system was activated
    /// against a KMS server (legitimate org KMS or KMSpico-hosted fake).
    /// Source: <c>https://learn.microsoft.com/windows-server/get-started/kms-client-activation-keys</c>
    /// </summary>
    private static readonly Dictionary<string, string> KnownGvlkSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows 10/11
        ["T83GX"] = "Windows 10/11 Pro (GVLK)",
        ["MH37W"] = "Windows 10/11 Pro N (GVLK)",
        ["6Q84J"] = "Windows 10/11 Pro for Workstations (GVLK)",
        ["WYRMJ"] = "Windows 10/11 Pro for Workstations N (GVLK)",
        ["2WH4N"] = "Windows 10/11 Pro Education (GVLK)",
        ["YVWGF"] = "Windows 10/11 Pro Education N (GVLK)",
        ["NW6C2"] = "Windows 10/11 Education (GVLK)",
        ["2J62F"] = "Windows 10/11 Education N (GVLK)",
        ["NPPR9"] = "Windows 10/11 Enterprise (GVLK)",
        ["DPH2V"] = "Windows 10/11 Enterprise N (GVLK)",
        ["YDRBP"] = "Windows 10/11 Enterprise G (GVLK)",
        ["44RPN"] = "Windows 10/11 Enterprise G N (GVLK)",
        ["WQ4NM"] = "Windows 10/11 Enterprise LTSC 2019 (GVLK)",
        ["M4FGT"] = "Windows 10/11 Enterprise LTSC 2021 (GVLK)",
        ["KBN8V"] = "Windows 10/11 Enterprise N LTSC 2021 (GVLK)",
        // Office 2019/LTSC 2021
        ["6MWKP"] = "Office Professional Plus 2019/2021 (GVLK)",
        ["MJMQJ"] = "Office Standard 2019/2021 (GVLK)",
    };

    /// <summary>
    /// Inspect Windows + Office license entries plus on-disk artifacts. Both inputs may
    /// be empty — the artifact scan still runs and can fire on a "post-mortem" install
    /// where the cracker activated then was partially uninstalled but left files behind.
    /// </summary>
    public (bool Suspected, IReadOnlyList<string> Evidence) Detect(
        LicenseInfo? windowsLicense,
        IReadOnlyList<LicenseInfo> officeLicenses)
    {
        var evidence = new List<string>();

        // === Signal 1 — KMS server pointed at a known-bad / loopback host ===
        var allLicenses = new List<LicenseInfo>();
        if (windowsLicense is not null)
        {
            allLicenses.Add(windowsLicense);
        }
        allLicenses.AddRange(officeLicenses);

        foreach (var lic in allLicenses)
        {
            if (string.IsNullOrEmpty(lic.KmsServer))
            {
                continue;
            }
            foreach (var bad in SuspiciousKmsHosts)
            {
                if (lic.KmsServer.Contains(bad, StringComparison.OrdinalIgnoreCase))
                {
                    evidence.Add($"License '{lic.Product}' trỏ tới KMS host đã biết là độc hại: {lic.KmsServer}");
                    break;
                }
            }
            var desc = lic.Description ?? string.Empty;
            bool isVolumeKms = desc.Contains("KMS", StringComparison.OrdinalIgnoreCase)
                            || desc.Contains("VOLUME", StringComparison.OrdinalIgnoreCase);
            if (isVolumeKms &&
                (lic.KmsServer.StartsWith("127.", StringComparison.Ordinal)
                 || lic.KmsServer.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
            {
                evidence.Add($"License '{lic.Product}' kích hoạt qua KMS loopback ({lic.KmsServer}) — đặc trưng KMSpico/AutoKMS");
            }
        }

        // === Signal 2 — known GVLK product key suffix on a non-domain workstation ===
        // GVLK is only legitimate when the workstation is joined to a domain that runs an
        // internal KMS host. On standalone Windows Home/Pro, a GVLK suffix is direct
        // evidence the machine was activated against a fake KMS (KMSpico/HEU/AutoKMS).
        foreach (var lic in allLicenses)
        {
            if (string.IsNullOrEmpty(lic.PartialProductKey))
            {
                continue;
            }
            var key = lic.PartialProductKey.Trim().ToUpperInvariant();
            if (KnownGvlkSuffixes.TryGetValue(key, out var label))
            {
                evidence.Add(
                    $"License '{lic.Product}' dùng key generic GVLK ({key} = {label}). "
                    + "GVLK chỉ hợp pháp trên máy tham gia domain có KMS nội bộ — máy đứng riêng dùng GVLK = KMSpico/AutoKMS/HEU.");
            }
        }

        // === Signal 3 — cracker binaries / install folders on disk ===
        // Walk system drive root + Program Files variants + ProgramData + WINDIR.
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System))
                          ?? @"C:\";
        var roots = new List<string?>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetEnvironmentVariable("WINDIR"),
            Path.Combine(Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows", "System32"),
            Path.Combine(Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows", "AutoKMS"),
            systemDrive
        };
        foreach (var root in roots.Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r)))
        {
            // 3a — directory names
            foreach (var dirSuffix in KmsToolDirectoryNames)
            {
                try
                {
                    var combined = Path.Combine(root!, dirSuffix.TrimStart('\\'));
                    if (Directory.Exists(combined))
                    {
                        evidence.Add($"Thư mục cài đặt cracker tồn tại: {combined}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Directory probe failed for {Root}{Suffix}", root, dirSuffix);
                }
            }
            // 3b — filenames in the immediate folder
            foreach (var fn in KmsToolFilenames)
            {
                try
                {
                    var matches = Directory.EnumerateFiles(root!, fn, SearchOption.TopDirectoryOnly).Take(1);
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

        // === Signal 4 — scheduled tasks ===
        try
        {
            var taskNames = _registry.GetSubKeyNames(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
            foreach (var t in taskNames)
            {
                if (t.Contains("AutoPico", StringComparison.OrdinalIgnoreCase)
                    || t.Contains("AutoKMS", StringComparison.OrdinalIgnoreCase)
                    || t.Contains("KMS-VL-ALL", StringComparison.OrdinalIgnoreCase)
                    || t.Contains("OfficeRefresher", StringComparison.OrdinalIgnoreCase)
                    || t.Contains("HEU_KMS", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("KMSpico", StringComparison.OrdinalIgnoreCase))
                {
                    evidence.Add($"Scheduled task tồn tại: {t} — persistence điển hình của KMSpico/AutoKMS/HEU");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Scheduled task registry enumeration failed");
        }

        // === Signal 5 — hosts file: lines redirecting Microsoft activation domains ===
        try
        {
            var hostsPath = Path.Combine(
                Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows",
                @"System32\drivers\etc\hosts");
            if (File.Exists(hostsPath))
            {
                using var sr = new StreamReader(hostsPath);
                int lineNo = 0;
                string? line;
                while ((line = sr.ReadLine()) is not null)
                {
                    lineNo++;
                    if (lineNo > 500)
                    {
                        break; // safety cap
                    }
                    var trimmed = line.TrimStart();
                    if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                    {
                        continue;
                    }
                    var lower = trimmed.ToLowerInvariant();
                    if ((lower.Contains("microsoft.com") || lower.Contains("activation.sls")
                         || lower.Contains("vlmcs") || lower.Contains("kms"))
                        && (lower.StartsWith("0.0.0.0") || lower.StartsWith("127.")
                            || lower.StartsWith("::1")))
                    {
                        evidence.Add($"Hosts file dòng {lineNo} chặn/redirect domain kích hoạt: '{trimmed}'");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Hosts file inspection failed");
        }

        // === Signal 6 — Defender exclusion paths pointing to suspicious folders ===
        // KMSpico installer typically adds %ProgramData%\KMSpico\ to the Defender exclusion
        // list so the real-time scan doesn't quarantine its renewal binary.
        try
        {
            var exclusions = _registry.GetValueNames(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
            foreach (var ex in exclusions)
            {
                var lower = ex.ToLowerInvariant();
                if (lower.Contains("kmspico") || lower.Contains("kmsauto")
                    || lower.Contains("autokms") || lower.Contains("heu")
                    || lower.Contains("toolkit") || lower.Contains("re-loader")
                    || lower.Contains("activator"))
                {
                    evidence.Add($"Defender exclusion trỏ tới đường dẫn nghi vấn: '{ex}'");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Defender exclusion read failed (key likely absent)");
        }

        return (evidence.Count > 0, evidence);
    }
}
