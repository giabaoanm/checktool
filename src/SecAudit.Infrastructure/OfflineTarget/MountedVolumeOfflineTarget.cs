using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// Audits a Windows volume that was mounted under another drive letter (WinPE/Mini-Windows
/// boot-USB scenario). Loads <c>SOFTWARE</c> and <c>SYSTEM</c> hives from
/// <c>&lt;volume&gt;\Windows\System32\config\</c> under a disposable HKLM subkey via
/// <c>RegLoadKey</c>, then <c>RegUnLoadKey</c> on <see cref="Dispose"/>.
///
/// Requires SE_BACKUP and SE_RESTORE privileges — i.e. an elevated process. Also requires
/// that the hive files are not already loaded by another process (WinPE itself loads its
/// own hives from the boot image, not from the target volume, so this is fine).
///
/// Per-user NTUSER.DAT hives are NOT loaded — offline HKCU reads return empty. Modules that
/// enumerate autostart entries fall back to HKLM-only scanning in that case, which is
/// acceptable because the common RAT/persistence footholds (Run keys, Services, WMI
/// subscriptions) are rooted in HKLM anyway.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MountedVolumeOfflineTarget : IOfflineTarget, IDisposable
{
    // HKEY_LOCAL_MACHINE — RegLoadKey takes a predefined handle.
    private static readonly IntPtr HKLM = unchecked((IntPtr)(int)0x80000002);

    private readonly string _softwareKey;
    private readonly string _systemKey;
    private bool _softwareLoaded;
    private bool _systemLoaded;

    public bool IsLive => false;
    public string SystemDrive { get; }
    public string WindowsDirectory { get; }
    public string UsersDirectory { get; }
    public string? LoadedSoftwareHiveKey => _softwareLoaded ? _softwareKey : null;
    public string? LoadedSystemHiveKey => _systemLoaded ? _systemKey : null;

    public MountedVolumeOfflineTarget(string volumeRoot)
    {
        if (string.IsNullOrWhiteSpace(volumeRoot))
        {
            throw new ArgumentException("volumeRoot required (e.g. 'D:\\').", nameof(volumeRoot));
        }
        // Normalise e.g. "D:" -> "D:\", and strip trailing backslash for Path.Combine uniformity.
        var normalised = volumeRoot.Trim();
        if (normalised.Length == 2 && normalised[1] == ':')
        {
            normalised += Path.DirectorySeparatorChar;
        }
        var trimmed = normalised.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var windowsDir = Path.Combine(trimmed, "Windows");
        if (!Directory.Exists(windowsDir))
        {
            throw new DirectoryNotFoundException(
                $"Windows folder not found at '{windowsDir}'. Is '{volumeRoot}' the Windows volume you want to audit?");
        }
        var configDir = Path.Combine(windowsDir, "System32", "config");
        var softwareHive = Path.Combine(configDir, "SOFTWARE");
        var systemHive = Path.Combine(configDir, "SYSTEM");
        if (!File.Exists(softwareHive))
        {
            throw new FileNotFoundException($"SOFTWARE hive missing at '{softwareHive}'.", softwareHive);
        }
        if (!File.Exists(systemHive))
        {
            throw new FileNotFoundException($"SYSTEM hive missing at '{systemHive}'.", systemHive);
        }

        SystemDrive = trimmed + Path.DirectorySeparatorChar;
        WindowsDirectory = windowsDir;
        UsersDirectory = Path.Combine(trimmed, "Users");

        // Unique suffix prevents collisions if multiple audits run concurrently (unusual but
        // possible if invoked from a task scheduler).
        var suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
        _softwareKey = $"SecAudit_Offline_{suffix}_SOFTWARE";
        _systemKey = $"SecAudit_Offline_{suffix}_SYSTEM";

        Privilege.Enable(Privilege.SE_BACKUP_NAME);
        Privilege.Enable(Privilege.SE_RESTORE_NAME);

        int rc = RegLoadKey(HKLM, _softwareKey, softwareHive);
        if (rc != 0)
        {
            throw new Win32Exception(rc, $"RegLoadKey(SOFTWARE → {_softwareKey}) failed.");
        }
        _softwareLoaded = true;
        try
        {
            rc = RegLoadKey(HKLM, _systemKey, systemHive);
            if (rc != 0)
            {
                throw new Win32Exception(rc, $"RegLoadKey(SYSTEM → {_systemKey}) failed.");
            }
            _systemLoaded = true;
        }
        catch
        {
            // Roll back the first load so we don't leak a loaded hive under HKLM if the
            // second one fails (common cause: permission denied when another process holds it).
            SafeUnload(_softwareKey);
            _softwareLoaded = false;
            throw;
        }
    }

    public void Dispose()
    {
        // Any RegistryKey objects opened against the loaded subkeys hold the hive open and
        // make RegUnLoadKey return ERROR_SHARING_VIOLATION (32). Force a GC pass so those
        // finalise before we try to unload.
        if (_softwareLoaded || _systemLoaded)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
        if (_systemLoaded)
        {
            SafeUnload(_systemKey);
            _systemLoaded = false;
        }
        if (_softwareLoaded)
        {
            SafeUnload(_softwareKey);
            _softwareLoaded = false;
        }
    }

    private static void SafeUnload(string subKey)
    {
        // Swallow errors — this runs in Dispose; log-and-move-on is the only sensible policy.
        // Common codes: 32 (SHARING_VIOLATION) when caller leaked a key handle, 2 (NOT_FOUND)
        // if RegLoadKey already failed.
        _ = RegUnLoadKey(HKLM, subKey);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "RegLoadKeyW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "RegUnLoadKeyW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);
}
