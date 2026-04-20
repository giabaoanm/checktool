namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// Abstracts the audit data source so modules can read from the live OS (default) OR an offline
/// Windows volume mounted under a drive letter (WinPE / Mini-Windows boot-USB scenario — Iteration 7).
///
/// The live implementation (<see cref="LiveOfflineTarget"/>) is registered by default. When the
/// CLI is invoked with <c>--offline &lt;drive&gt;</c> the composition root swaps in
/// <see cref="MountedVolumeOfflineTarget"/>, which loads the target volume's SOFTWARE and SYSTEM
/// hives under a disposable HKLM subkey. All registry lookups transparently translate
/// <c>HKLM\SOFTWARE\...</c> → <c>HKLM\&lt;LoadedSoftwareHiveKey&gt;\...</c> so call-sites are
/// identical in both modes.
/// </summary>
public interface IOfflineTarget
{
    /// <summary>True when auditing the live running OS, false when auditing a mounted volume.</summary>
    bool IsLive { get; }

    /// <summary>
    /// Root of the target Windows install.
    /// Live: usually <c>C:\</c> (from %SystemDrive%). Offline: e.g., <c>D:\</c>.
    /// </summary>
    string SystemDrive { get; }

    /// <summary>Path to the Windows directory (e.g., <c>C:\Windows</c>).</summary>
    string WindowsDirectory { get; }

    /// <summary>Path to the Users folder (e.g., <c>C:\Users</c>).</summary>
    string UsersDirectory { get; }

    /// <summary>
    /// When Offline, the HKLM subkey name where the target's SOFTWARE hive is currently
    /// loaded (e.g., <c>SecAudit_Offline_abc12345_SOFTWARE</c>). Null when Live — callers must
    /// use the native HKLM\SOFTWARE path in that case.
    /// </summary>
    string? LoadedSoftwareHiveKey { get; }

    /// <summary>
    /// When Offline, the HKLM subkey name where the target's SYSTEM hive is currently loaded.
    /// Null when Live.
    /// </summary>
    string? LoadedSystemHiveKey { get; }
}
