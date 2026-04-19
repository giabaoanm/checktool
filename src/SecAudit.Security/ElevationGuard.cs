using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace SecAudit.Security;

[SupportedOSPlatform("windows")]
public static class ElevationGuard
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// If not elevated, relaunch the current process with the runas verb and return true so
    /// the caller can exit. If already elevated, returns false.
    /// </summary>
    public static bool TryRelaunchAsAdmin()
    {
        if (IsElevated())
        {
            return false;
        }
        var exe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine current process path.");
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory
        };
        try
        {
            using var p = Process.Start(psi);
            return p is not null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User declined UAC.
            return false;
        }
    }
}
