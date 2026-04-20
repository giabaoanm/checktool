using SecAudit.Infrastructure.OfflineTarget;

namespace SecAudit.Modules.RemoteAccess.Tests;

/// <summary>
/// Test stub that lets us point <see cref="IOfflineTarget.WindowsDirectory"/> at a fixture
/// folder containing a <c>System32\Tasks\</c> subtree. The detector walks that subtree so
/// this is all we need for hermetic testing.
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
