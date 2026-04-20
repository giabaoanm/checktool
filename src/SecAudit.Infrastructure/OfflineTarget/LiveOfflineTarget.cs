using System.Runtime.Versioning;

namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// Default target: the live running Windows installation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LiveOfflineTarget : IOfflineTarget
{
    public bool IsLive => true;

    public string SystemDrive { get; } =
        Environment.GetEnvironmentVariable("SystemDrive") is { Length: > 0 } d
            ? d + Path.DirectorySeparatorChar
            : @"C:\";

    public string WindowsDirectory { get; } =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public string UsersDirectory { get; } =
        Path.Combine(
            Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
                ?? @"C:\",
            "Users");

    // Live mode uses the native HKLM\SOFTWARE / HKLM\SYSTEM paths, so no redirect keys.
    public string? LoadedSoftwareHiveKey => null;
    public string? LoadedSystemHiveKey => null;
}
