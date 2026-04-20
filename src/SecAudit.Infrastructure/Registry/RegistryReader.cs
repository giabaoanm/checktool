using System.Runtime.Versioning;
using Microsoft.Win32;
using SecAudit.Infrastructure.OfflineTarget;
using NativeHive = Microsoft.Win32.RegistryHive;

namespace SecAudit.Infrastructure.Registry;

/// <summary>
/// Offline-aware registry reader.
///
/// Live mode (<see cref="LiveOfflineTarget"/>): behaves exactly like a straight
/// <see cref="RegistryKey.OpenBaseKey"/> wrapper.
///
/// Offline mode (<see cref="MountedVolumeOfflineTarget"/>): the target has loaded the
/// volume's SOFTWARE and SYSTEM hives under a disposable HKLM subkey. Lookups to
/// <c>HKLM\SOFTWARE\...</c> are transparently redirected to
/// <c>HKLM\&lt;LoadedSoftwareHiveKey&gt;\...</c>, likewise for SYSTEM. HKCU/HKU/HKCR return
/// empty in offline mode — this is intentional (NTUSER.DAT loading is out of scope for the
/// MVP). Callers relying on HKCU fall back gracefully.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryReader : IRegistryReader
{
    private readonly IOfflineTarget _target;

    public RegistryReader(IOfflineTarget target)
    {
        _target = target;
    }

    public object? GetValue(RegistryHive hive, string subKey, string valueName, bool view64 = true)
    {
        using var baseKey = OpenBase(hive, view64);
        if (baseKey is null) { return null; }
        var path = Translate(hive, subKey);
        if (path is null) { return null; }
        using var key = baseKey.OpenSubKey(path, writable: false);
        return key?.GetValue(valueName);
    }

    public IReadOnlyList<string> GetSubKeyNames(RegistryHive hive, string subKey, bool view64 = true)
    {
        using var baseKey = OpenBase(hive, view64);
        if (baseKey is null) { return Array.Empty<string>(); }
        var path = Translate(hive, subKey);
        if (path is null) { return Array.Empty<string>(); }
        using var key = baseKey.OpenSubKey(path, writable: false);
        return key?.GetSubKeyNames() ?? Array.Empty<string>();
    }

    public IReadOnlyList<string> GetValueNames(RegistryHive hive, string subKey, bool view64 = true)
    {
        using var baseKey = OpenBase(hive, view64);
        if (baseKey is null) { return Array.Empty<string>(); }
        var path = Translate(hive, subKey);
        if (path is null) { return Array.Empty<string>(); }
        using var key = baseKey.OpenSubKey(path, writable: false);
        return key?.GetValueNames() ?? Array.Empty<string>();
    }

    /// <summary>
    /// Maps a (hive, subKey) pair into an actual subKey under HKLM (or another real hive).
    /// Returns null if the combination is unsupported in the current mode (e.g. HKCU offline).
    /// Exposed <see langword="internal"/> for unit tests — see
    /// <c>SecAudit.Infrastructure.Tests.RegistryReaderOfflineTranslateTests</c>.
    /// </summary>
    internal string? Translate(RegistryHive hive, string subKey)
    {
        if (_target.IsLive)
        {
            return subKey;
        }

        // Offline mode — only HKLM\SOFTWARE and HKLM\SYSTEM are supported.
        if (hive != RegistryHive.LocalMachine)
        {
            return null;
        }

        var path = subKey ?? string.Empty;
        // Case-insensitive prefix match on "SOFTWARE" or "SYSTEM".
        if (StartsWithSegment(path, "SOFTWARE", out var rest) && _target.LoadedSoftwareHiveKey is { } swKey)
        {
            return rest.Length == 0 ? swKey : $"{swKey}\\{rest}";
        }
        if (StartsWithSegment(path, "SYSTEM", out rest) && _target.LoadedSystemHiveKey is { } syKey)
        {
            return rest.Length == 0 ? syKey : $"{syKey}\\{rest}";
        }
        return null;
    }

    /// <summary>
    /// Returns true if <paramref name="path"/> starts with <paramref name="segment"/> followed
    /// by either end-of-string or a backslash (case-insensitive). Writes the remainder to
    /// <paramref name="rest"/> with the leading backslash trimmed.
    /// </summary>
    internal static bool StartsWithSegment(string path, string segment, out string rest)
    {
        if (path.Length < segment.Length ||
            !path.StartsWith(segment, StringComparison.OrdinalIgnoreCase))
        {
            rest = string.Empty;
            return false;
        }
        if (path.Length == segment.Length)
        {
            rest = string.Empty;
            return true;
        }
        char next = path[segment.Length];
        if (next != '\\' && next != '/')
        {
            rest = string.Empty;
            return false;
        }
        rest = path.Substring(segment.Length + 1);
        return true;
    }

    /// <summary>Opens the base hive — in offline mode all supported hives live under HKLM.</summary>
    private RegistryKey? OpenBase(RegistryHive hive, bool view64)
    {
        var view = view64 ? RegistryView.Registry64 : RegistryView.Registry32;
        if (!_target.IsLive)
        {
            // Offline mode: all redirected paths live under HKLM.
            if (hive != RegistryHive.LocalMachine)
            {
                return null;
            }
            return RegistryKey.OpenBaseKey(NativeHive.LocalMachine, view);
        }
        var native = hive switch
        {
            RegistryHive.LocalMachine => NativeHive.LocalMachine,
            RegistryHive.CurrentUser => NativeHive.CurrentUser,
            RegistryHive.Users => NativeHive.Users,
            RegistryHive.ClassesRoot => NativeHive.ClassesRoot,
            _ => throw new ArgumentOutOfRangeException(nameof(hive))
        };
        return RegistryKey.OpenBaseKey(native, view);
    }
}
