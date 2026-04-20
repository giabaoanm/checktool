using System.Runtime.Versioning;
using NativeRegistry = Microsoft.Win32.Registry;

namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// Detects whether SecAudit is running inside a WinPE / Mini-Windows environment.
/// Useful for the CLI to print "You appear to be in WinPE — did you mean to pass --offline?"
/// </summary>
[SupportedOSPlatform("windows")]
public static class WinPeEnvironment
{
    /// <summary>
    /// WinPE sets <c>HKLM\SYSTEM\ControlSet001\Control\MiniNT</c>. Absent on a normal Windows
    /// install; present on any WPS/WinPE image. See MS docs "WinPE: Identify Winpe".
    /// </summary>
    public static bool IsRunningInWinPe()
    {
        try
        {
            using var key = NativeRegistry.LocalMachine.OpenSubKey(@"SYSTEM\ControlSet001\Control\MiniNT");
            return key is not null;
        }
        catch
        {
            return false;
        }
    }
}
