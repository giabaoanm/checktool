using System.Reflection;
using FluentAssertions;
using SecAudit.Modules.RemoteAccess.Detectors;
using Xunit;

namespace SecAudit.Modules.RemoteAccess.Tests;

public sealed class PersistenceDetectorTests
{
    [Fact]
    public void Classify_suppresses_bing_wallpaper_temp_uninstaller()
    {
        var result = InvokeClassify(
            @"C:\Users\Admin\AppData\Local\Temp\bwpea3935d0-159f-46f6-9b84-ccb5600ecbfe\UnInstDaemon.exe");

        result.Suspicious.Should().BeFalse();
    }

    [Fact]
    public void Classify_keeps_generic_temp_autorun_suspicious()
    {
        var result = InvokeClassify(
            @"C:\Users\Admin\AppData\Local\Temp\random\payload.exe");

        result.Suspicious.Should().BeTrue();
        result.Reason.Should().Contain("user-writable");
    }

    private static (bool Suspicious, string? Reason) InvokeClassify(string command)
    {
        var method = typeof(PersistenceDetector).GetMethod(
            "Classify",
            BindingFlags.NonPublic | BindingFlags.Static);

        method.Should().NotBeNull();
        var result = method!.Invoke(null, new object[] { command });
        result.Should().NotBeNull();

        var suspicious = (bool)result!.GetType().GetField("Item1")!.GetValue(result)!;
        var reason = (string?)result.GetType().GetField("Item2")!.GetValue(result);
        return (suspicious, reason);
    }
}
