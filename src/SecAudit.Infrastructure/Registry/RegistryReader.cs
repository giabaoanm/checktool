using System.Runtime.Versioning;
using Microsoft.Win32;
using NativeHive = Microsoft.Win32.RegistryHive;

namespace SecAudit.Infrastructure.Registry;

[SupportedOSPlatform("windows")]
public sealed class RegistryReader : IRegistryReader
{
    public object? GetValue(RegistryHive hive, string subKey, string valueName, bool view64 = true)
    {
        using var baseKey = OpenBase(hive, view64);
        using var key = baseKey.OpenSubKey(subKey, writable: false);
        return key?.GetValue(valueName);
    }

    public IReadOnlyList<string> GetSubKeyNames(RegistryHive hive, string subKey, bool view64 = true)
    {
        using var baseKey = OpenBase(hive, view64);
        using var key = baseKey.OpenSubKey(subKey, writable: false);
        return key?.GetSubKeyNames() ?? Array.Empty<string>();
    }

    public IReadOnlyList<string> GetValueNames(RegistryHive hive, string subKey, bool view64 = true)
    {
        using var baseKey = OpenBase(hive, view64);
        using var key = baseKey.OpenSubKey(subKey, writable: false);
        return key?.GetValueNames() ?? Array.Empty<string>();
    }

    private static RegistryKey OpenBase(RegistryHive hive, bool view64)
    {
        var native = hive switch
        {
            RegistryHive.LocalMachine => NativeHive.LocalMachine,
            RegistryHive.CurrentUser => NativeHive.CurrentUser,
            RegistryHive.Users => NativeHive.Users,
            RegistryHive.ClassesRoot => NativeHive.ClassesRoot,
            _ => throw new ArgumentOutOfRangeException(nameof(hive))
        };
        return RegistryKey.OpenBaseKey(native, view64 ? RegistryView.Registry64 : RegistryView.Registry32);
    }
}
