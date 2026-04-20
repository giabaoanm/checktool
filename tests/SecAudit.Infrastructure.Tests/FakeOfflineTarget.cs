using SecAudit.Infrastructure.OfflineTarget;

namespace SecAudit.Infrastructure.Tests;

/// <summary>
/// Minimal <see cref="IOfflineTarget"/> stub for unit tests. Defaults model a LIVE target;
/// tests flip <see cref="IsLive"/> and plug in <see cref="LoadedSoftwareHiveKey"/> /
/// <see cref="LoadedSystemHiveKey"/> to simulate a mounted-volume (WinPE) target.
/// </summary>
internal sealed class FakeOfflineTarget : IOfflineTarget
{
    public bool IsLive { get; init; } = true;
    public string SystemDrive { get; init; } = @"C:\";
    public string WindowsDirectory { get; init; } = @"C:\Windows";
    public string UsersDirectory { get; init; } = @"C:\Users";
    public string? LoadedSoftwareHiveKey { get; init; }
    public string? LoadedSystemHiveKey { get; init; }
}
