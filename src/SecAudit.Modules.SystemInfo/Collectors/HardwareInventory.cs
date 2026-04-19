using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Infrastructure.Wmi;
using SecAudit.Modules.SystemInfo.Models;

namespace SecAudit.Modules.SystemInfo.Collectors;

[SupportedOSPlatform("windows")]
public sealed class HardwareInventory
{
    private readonly IWmiQuery _wmi;
    private readonly IRegistryReader _registry;
    private readonly ILogger<HardwareInventory> _logger;

    public HardwareInventory(IWmiQuery wmi, IRegistryReader registry, ILogger<HardwareInventory> logger)
    {
        _wmi = wmi;
        _registry = registry;
        _logger = logger;
    }

    public (HardwareInfo Hardware, OsInfo Os) Collect()
    {
        var cs = _wmi.Query(@"\\.\ROOT\CIMV2", "SELECT Manufacturer, Model FROM Win32_ComputerSystem")
            .FirstOrDefault();
        var bios = _wmi.Query(@"\\.\ROOT\CIMV2",
            "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_BIOS")
            .FirstOrDefault();
        var cpu = _wmi.Query(@"\\.\ROOT\CIMV2",
            "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor")
            .FirstOrDefault();
        var os = _wmi.Query(@"\\.\ROOT\CIMV2",
            "SELECT Caption, Version, BuildNumber, InstallDate, OSArchitecture, LastBootUpTime, TotalVisibleMemorySize FROM Win32_OperatingSystem")
            .FirstOrDefault();

        var ramBytes = 0L;
        foreach (var m in _wmi.Query(@"\\.\ROOT\CIMV2", "SELECT Capacity FROM Win32_PhysicalMemory"))
        {
            if (m.TryGetValue("Capacity", out var c) && c is not null
                && ulong.TryParse(c.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var cap))
            {
                ramBytes += (long)cap;
            }
        }

        var disks = new List<DiskDriveInfo>();
        foreach (var d in _wmi.Query(@"\\.\ROOT\CIMV2",
            "SELECT Model, InterfaceType, Size, SerialNumber FROM Win32_DiskDrive"))
        {
            var size = 0L;
            if (d.TryGetValue("Size", out var s) && s is not null
                && long.TryParse(s.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var sz))
            {
                size = sz;
            }
            disks.Add(new DiskDriveInfo(
                Model: Str(d, "Model") ?? "Unknown",
                InterfaceType: Str(d, "InterfaceType") ?? "",
                SizeBytes: size,
                SerialNumber: Str(d, "SerialNumber")));
        }

        // TPM
        var tpmPresent = false;
        string? tpmSpec = null;
        try
        {
            var tpm = _wmi.Query(@"\\.\ROOT\CIMV2\Security\MicrosoftTpm",
                "SELECT IsEnabled_InitialValue, SpecVersion FROM Win32_Tpm").FirstOrDefault();
            if (tpm is not null)
            {
                tpmPresent = true;
                tpmSpec = Str(tpm, "SpecVersion");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "TPM query failed (not present or no permission)");
        }

        // Secure Boot from registry
        var secureBoot = false;
        try
        {
            var val = _registry.GetValue(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled");
            secureBoot = val is int i && i == 1;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SecureBoot registry read failed");
        }

        var hw = new HardwareInfo(
            Manufacturer: Str(cs, "Manufacturer") ?? "Unknown",
            Model: Str(cs, "Model") ?? "Unknown",
            SerialNumber: Str(bios, "SerialNumber") ?? "",
            BiosVendor: Str(bios, "Manufacturer") ?? "",
            BiosVersion: Str(bios, "SMBIOSBIOSVersion") ?? "",
            BiosReleaseDate: ParseWmiDate(Str(bios, "ReleaseDate")),
            CpuName: Str(cpu, "Name")?.Trim() ?? "Unknown",
            CpuCores: Int(cpu, "NumberOfCores"),
            CpuLogicalProcessors: Int(cpu, "NumberOfLogicalProcessors"),
            TotalPhysicalMemoryBytes: ramBytes,
            Disks: disks,
            TpmPresent: tpmPresent,
            TpmSpecVersion: tpmSpec,
            SecureBootEnabled: secureBoot);

        var osInfo = new OsInfo(
            Caption: Str(os, "Caption") ?? "Unknown",
            Version: Str(os, "Version") ?? "",
            BuildNumber: Str(os, "BuildNumber") ?? "",
            DisplayVersion: ReadDisplayVersion(),
            InstallDate: Str(os, "InstallDate") ?? "",
            Architecture: Str(os, "OSArchitecture") ?? "",
            LastBootUpTime: Str(os, "LastBootUpTime") ?? "");

        return (hw, osInfo);
    }

    private string ReadDisplayVersion()
    {
        try
        {
            return _registry.GetValue(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "DisplayVersion")?.ToString()
                ?? _registry.GetValue(
                    RegistryHive.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    "ReleaseId")?.ToString()
                ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string? Str(IReadOnlyDictionary<string, object?>? dict, string key)
        => dict is not null && dict.TryGetValue(key, out var v) ? v?.ToString() : null;

    private static int Int(IReadOnlyDictionary<string, object?>? dict, string key)
    {
        var s = Str(dict, key);
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
    }

    private static DateTimeOffset? ParseWmiDate(string? wmiDate)
    {
        // WMI CIM_DATETIME: yyyymmddHHMMSS.ffffff+UUU
        if (string.IsNullOrEmpty(wmiDate) || wmiDate.Length < 14)
        {
            return null;
        }
        try
        {
            var y = int.Parse(wmiDate.AsSpan(0, 4), NumberStyles.Integer, CultureInfo.InvariantCulture);
            var mo = int.Parse(wmiDate.AsSpan(4, 2), NumberStyles.Integer, CultureInfo.InvariantCulture);
            var d = int.Parse(wmiDate.AsSpan(6, 2), NumberStyles.Integer, CultureInfo.InvariantCulture);
            return new DateTimeOffset(y, mo, d, 0, 0, 0, TimeSpan.Zero);
        }
        catch
        {
            return null;
        }
    }
}
