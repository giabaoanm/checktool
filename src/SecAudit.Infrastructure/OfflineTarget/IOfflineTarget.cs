namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// Abstracts the audit data source so modules can read from the live OS (default) OR an offline
/// Windows volume mounted under a drive letter (WinPE / Mini-Windows boot-USB scenario — Iteration 7).
///
/// Iteration 1 introduces the contract only. Modules that accept an <see cref="IOfflineTarget"/>
/// today resolve the <see cref="LiveOfflineTarget"/> implementation, which is a pass-through
/// marker for "this is the live running OS". Iteration 7 will add <c>MountedVolumeOfflineTarget</c>
/// which loads registry hives via <c>reg load</c> and rebases all file paths under the target root.
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
}
