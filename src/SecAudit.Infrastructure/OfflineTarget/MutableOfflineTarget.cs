using System.Runtime.Versioning;

namespace SecAudit.Infrastructure.OfflineTarget;

/// <summary>
/// An <see cref="IOfflineTarget"/> wrapper whose underlying delegate can be swapped at
/// runtime. Lets the WPF shell start with a <see cref="LiveOfflineTarget"/> at app
/// boot and switch to a <see cref="MountedVolumeOfflineTarget"/> just before running an
/// offline-volume audit.
///
/// <para>
/// Why this is needed: the GUI uses dependency injection to wire <see cref="IOfflineTarget"/>
/// into <c>RegistryReader</c>, every collector, and every module. DI containers don't
/// support replacing a registered singleton at runtime, so without an indirection layer
/// the only way to switch from live to offline mode would be to rebuild the host (and
/// every module/cache inside it). The wrapper avoids that — modules keep the same
/// reference; only the inner delegate changes.
/// </para>
///
/// <para>
/// Lifecycle: when <see cref="Switch"/> replaces a <see cref="MountedVolumeOfflineTarget"/>
/// the previous one is disposed, which un-mounts the SOFTWARE/SYSTEM hives via
/// <c>RegUnLoadKey</c>. Callers MUST reset back to a live target before exiting the
/// audit run, otherwise the loaded hives persist under HKLM until the process ends —
/// usually harmless but visually confusing in a Registry Editor.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MutableOfflineTarget : IOfflineTarget, IDisposable
{
    private IOfflineTarget _inner;

    public MutableOfflineTarget()
    {
        // App-start default: the live OS. Audit code paths consume IOfflineTarget
        // from DI before any user interaction, so the wrapper must be valid from t=0.
        _inner = new LiveOfflineTarget();
    }

    /// <summary>
    /// Replace the inner target. The previous inner is disposed if it implements
    /// <see cref="IDisposable"/> (notably <see cref="MountedVolumeOfflineTarget"/>,
    /// which un-mounts hives on dispose).
    /// </summary>
    public void Switch(IOfflineTarget newInner)
    {
        ArgumentNullException.ThrowIfNull(newInner);
        var previous = _inner;
        _inner = newInner;
        (previous as IDisposable)?.Dispose();
    }

    /// <summary>Convenience for the common "audit done, go back to live" pattern.</summary>
    public void ResetToLive() => Switch(new LiveOfflineTarget());

    public bool IsLive => _inner.IsLive;
    public string SystemDrive => _inner.SystemDrive;
    public string WindowsDirectory => _inner.WindowsDirectory;
    public string UsersDirectory => _inner.UsersDirectory;
    public string? LoadedSoftwareHiveKey => _inner.LoadedSoftwareHiveKey;
    public string? LoadedSystemHiveKey => _inner.LoadedSystemHiveKey;

    public void Dispose()
    {
        (_inner as IDisposable)?.Dispose();
    }
}
