using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// Enables a named privilege (e.g. <c>SeBackupPrivilege</c>, <c>SeRestorePrivilege</c>) on the
/// current process token. Required before <c>RegLoadKey</c> will accept a file hive.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class Privilege
{
    internal const string SE_BACKUP_NAME = "SeBackupPrivilege";
    internal const string SE_RESTORE_NAME = "SeRestorePrivilege";

    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle, bool disableAll, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>
    /// Enables <paramref name="name"/> on the current process token. Throws
    /// <see cref="Win32Exception"/> if the token doesn't hold it (i.e. not running as admin).
    /// </summary>
    public static void Enable(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcessToken failed for privilege '{name}'");
        }
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"LookupPrivilegeValue('{name}') failed");
            }
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
            };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"AdjustTokenPrivileges('{name}') failed");
            }
            // AdjustTokenPrivileges returns true even when the token doesn't hold the
            // requested privilege — the error is surfaced via GetLastError = 1300.
            int err = Marshal.GetLastWin32Error();
            if (err == ERROR_NOT_ALL_ASSIGNED)
            {
                throw new Win32Exception(err,
                    $"Privilege '{name}' is not held by this token. Run SecAudit elevated (Administrator).");
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
