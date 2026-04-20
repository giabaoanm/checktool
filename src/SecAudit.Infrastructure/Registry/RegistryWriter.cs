using System.Runtime.Versioning;
using Microsoft.Win32;
using NativeHive = Microsoft.Win32.RegistryHive;
using NativeKind = Microsoft.Win32.RegistryValueKind;

namespace SecAudit.Infrastructure.Registry;

[SupportedOSPlatform("windows")]
public sealed class RegistryWriter : IRegistryWriter
{
    public void SetValue(
        RegistryHive hive,
        string subKey,
        string valueName,
        object value,
        RegistryValueKind kind,
        bool view64 = true)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentException.ThrowIfNullOrWhiteSpace(subKey);

        using var baseKey = OpenBase(hive, view64);
        // CreateSubKey opens-or-creates with writable=true.
        using var key = baseKey.CreateSubKey(subKey, writable: true)
            ?? throw new InvalidOperationException(
                $"Failed to open or create registry sub-key '{subKey}' under {hive}.");
        key.SetValue(valueName, value, MapKind(kind));
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

    private static NativeKind MapKind(RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.String => NativeKind.String,
        RegistryValueKind.DWord => NativeKind.DWord,
        RegistryValueKind.QWord => NativeKind.QWord,
        RegistryValueKind.MultiString => NativeKind.MultiString,
        RegistryValueKind.Binary => NativeKind.Binary,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}
