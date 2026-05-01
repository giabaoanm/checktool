using System.Runtime.Versioning;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SecAudit.Modules.RemoteAccess.Detectors;
using Xunit;

namespace SecAudit.Modules.RemoteAccess.Tests;

/// <summary>
/// Locks down the XML-walker in <see cref="ScheduledTasksXmlDetector"/>. The fixture tree
/// under <c>tests/Fixtures/win-tasks/System32/Tasks/</c> models a small but representative
/// Windows task store with both benign and RAT-style entries.
///
/// Each fixture file is designed to trigger ONE specific suspicious-fragment match so the
/// tests stay stable if the <c>SuspiciousFragments</c> array is reordered.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScheduledTasksXmlDetectorTests
{
    private static string FixtureWindowsDir()
    {
        // tests copy Fixtures\win-tasks\ into the assembly output dir via .csproj Link item.
        var here = AppContext.BaseDirectory;
        var candidate = Path.Combine(here, "Fixtures", "win-tasks");
        if (Directory.Exists(Path.Combine(candidate, "System32", "Tasks"))) { return candidate; }
        // Fallback for `dotnet test` direct runs without copy — walk up to the repo root.
        var dir = new DirectoryInfo(here);
        while (dir is not null)
        {
            var p = Path.Combine(dir.FullName, "tests", "Fixtures", "win-tasks");
            if (Directory.Exists(Path.Combine(p, "System32", "Tasks"))) { return p; }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(
            "Cannot locate tests/Fixtures/win-tasks relative to " + here);
    }

    private static ScheduledTasksXmlDetector BuildDetector()
    {
        return BuildDetectorForWindowsDir(FixtureWindowsDir());
    }

    private static ScheduledTasksXmlDetector BuildDetectorForWindowsDir(string windowsDir)
    {
        var target = new FakeOfflineTarget { WindowsDirectory = windowsDir };
        return new ScheduledTasksXmlDetector(target,
            NullLogger<ScheduledTasksXmlDetector>.Instance);
    }

    [Fact]
    public void Detect_flags_encoded_powershell_argument()
    {
        var results = BuildDetector().Detect();

        results.Should().Contain(t =>
            t.Path.EndsWith("encoded-ps", StringComparison.OrdinalIgnoreCase)
            && t.Reason.Contains("-enc", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_flags_iex_download_cradle()
    {
        var results = BuildDetector().Detect();

        results.Should().Contain(t =>
            t.Path.EndsWith("iex-downloader", StringComparison.OrdinalIgnoreCase)
            && (t.Reason.Contains("iex", StringComparison.OrdinalIgnoreCase)
                || t.Reason.Contains("downloadstring", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void Detect_flags_user_writable_drop_path()
    {
        var results = BuildDetector().Detect();

        results.Should().Contain(t =>
            t.Path.EndsWith("temp-dropper", StringComparison.OrdinalIgnoreCase)
            && t.Reason.Contains(@"\users\public\", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_flags_mshta_javascript_payload()
    {
        var results = BuildDetector().Detect();

        results.Should().Contain(t =>
            t.Path.EndsWith("mshta-hta", StringComparison.OrdinalIgnoreCase)
            && t.Reason.Contains("mshta", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_flags_regsvr32_scrobj_squiblydoo()
    {
        var results = BuildDetector().Detect();

        results.Should().Contain(t =>
            t.Path.EndsWith("regsvr32-squib", StringComparison.OrdinalIgnoreCase)
            && t.Reason.Contains("regsvr32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_ignores_benign_backup_task()
    {
        var results = BuildDetector().Detect();

        results.Should().NotContain(t =>
            t.Path.EndsWith("benign-backup", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_ignores_windows_defender_platform_tasks_under_programdata()
    {
        var root = Path.Combine(Path.GetTempPath(), "SecAudit.Tests.Tasks",
            Guid.NewGuid().ToString("N"));
        var taskDir = Path.Combine(root, "System32", "Tasks", "Microsoft", "Windows", "Windows Defender");
        Directory.CreateDirectory(taskDir);
        try
        {
            File.WriteAllText(Path.Combine(taskDir, "Windows Defender Scheduled Scan"),
                TaskXml(
                    @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26030.3011-0\MpCmdRun.exe",
                    "Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob"));

            BuildDetectorForWindowsDir(root).Detect().Should().BeEmpty();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Detect_ignores_firefox_background_update_programdata_log_path()
    {
        var root = Path.Combine(Path.GetTempPath(), "SecAudit.Tests.Tasks",
            Guid.NewGuid().ToString("N"));
        var taskDir = Path.Combine(root, "System32", "Tasks", "Mozilla");
        Directory.CreateDirectory(taskDir);
        try
        {
            File.WriteAllText(Path.Combine(taskDir, "Firefox Background Update S-1-5-21-test"),
                TaskXml(
                    @"C:\Program Files\Mozilla Firefox\firefox.exe",
                    @"--MOZ_LOG_FILE C:\ProgramData\Mozilla-test\updates\backgroundupdate.moz_log --backgroundtask backgroundupdate"));

            BuildDetectorForWindowsDir(root).Detect().Should().BeEmpty();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Detect_ignores_Microsoft_signed_defrag_task_in_subdirectory()
    {
        var results = BuildDetector().Detect();

        results.Should().NotContain(t =>
            t.Path.EndsWith("benign-defrag", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_swallows_non_xml_files_and_does_not_crash()
    {
        // broken.xml is garbage text — XDocument.Load will throw. Detector must catch and
        // continue; the other malicious tasks should still surface.
        var act = () => BuildDetector().Detect();

        act.Should().NotThrow();
        act().Should().Contain(t =>
            t.Path.EndsWith("encoded-ps", StringComparison.OrdinalIgnoreCase),
            because: "a single bad file must not abort the rest of the scan");
    }

    [Fact]
    public void Detect_emits_one_finding_per_task_even_if_multiple_fragments_match()
    {
        // iex-downloader matches BOTH "iex " AND "downloadstring"; fixture should still
        // produce exactly ONE result entry (dedup by file).
        var results = BuildDetector().Detect();

        results.Count(t =>
            t.Path.EndsWith("iex-downloader", StringComparison.OrdinalIgnoreCase))
               .Should().Be(1);
    }

    [Fact]
    public void Detect_returns_empty_when_tasks_root_missing()
    {
        // Point at a Windows directory that does not contain System32\Tasks — e.g. a
        // newly-formatted disk or a partial recovery mount. Must return empty list,
        // NOT throw.
        var bogus = Path.Combine(Path.GetTempPath(), "SecAudit.Tests.NoTasksDir",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(bogus);
        try
        {
            var target = new FakeOfflineTarget { WindowsDirectory = bogus };
            var detector = new ScheduledTasksXmlDetector(target,
                NullLogger<ScheduledTasksXmlDetector>.Instance);

            detector.Detect().Should().BeEmpty();
        }
        finally
        {
            Directory.Delete(bogus, recursive: true);
        }
    }

    [Fact]
    public void Detect_reports_path_relative_to_Tasks_root_with_forward_slashes()
    {
        // Paths in the report are trimmed of the "System32\Tasks\" prefix and use '/'
        // separators for cross-report consistency. Verify both normalization rules on the
        // nested Microsoft\Windows\benign-defrag fixture's SIBLING that is suspicious —
        // we use regsvr32-squib (at root) + verify no backslash leaks through.
        var results = BuildDetector().Detect();

        foreach (var r in results)
        {
            r.Path.Should().NotContain("\\",
                because: "detector must normalize separators to forward-slash");
            r.Path.Should().NotStartWith("System32",
                because: "paths must be relative to the Tasks root");
        }
    }

    private static string TaskXml(string command, string arguments) =>
        $$"""
        <?xml version="1.0" encoding="utf-8"?>
        <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Actions Context="Author">
            <Exec>
              <Command>{{System.Security.SecurityElement.Escape(command)}}</Command>
              <Arguments>{{System.Security.SecurityElement.Escape(arguments)}}</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;
}
