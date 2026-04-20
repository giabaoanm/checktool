using System.Runtime.Versioning;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.OfflineTarget;

namespace SecAudit.Modules.RemoteAccess.Detectors;

/// <summary>
/// Scans <c>%WINDIR%\System32\Tasks\**</c> XML definitions for scheduled-task persistence that
/// exhibits RAT-like patterns (encoded PowerShell, LOLBin invocation, drop-in user-writable
/// folders). Works in both live and offline mode — the task XML files are plain text on disk.
///
/// This is a signal on top of WMI <c>Schedule.Service</c> (used elsewhere): offline we can't
/// call the COM service, but the XML files still exist on the volume.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScheduledTasksXmlDetector
{
    public sealed record SuspiciousTask(string Path, string Command, string Reason);

    private static readonly string[] SuspiciousFragments =
    {
        "-enc ",
        "-encodedcommand",
        "iex ",
        "invoke-expression",
        "downloadstring",
        "downloadfile",
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\users\public\",
        @"\windows\temp\",
        @"\programdata\",
        "mshta",
        "regsvr32 /s /u /i:http",
        "rundll32.exe javascript:"
    };

    private readonly IOfflineTarget _target;
    private readonly ILogger<ScheduledTasksXmlDetector> _logger;

    public ScheduledTasksXmlDetector(IOfflineTarget target, ILogger<ScheduledTasksXmlDetector> logger)
    {
        _target = target;
        _logger = logger;
    }

    public IReadOnlyList<SuspiciousTask> Detect()
    {
        var results = new List<SuspiciousTask>();
        var tasksRoot = Path.Combine(_target.WindowsDirectory, "System32", "Tasks");
        if (!Directory.Exists(tasksRoot))
        {
            _logger.LogDebug("Tasks root not found: {Path}", tasksRoot);
            return results;
        }
        // Task XML files have no extension; enumerate everything and let the parser reject
        // non-XML files. Recurse — the "Microsoft\Windows\..." subtree contains hundreds.
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(tasksRoot, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not enumerate tasks under {Path}", tasksRoot);
            return results;
        }
        foreach (var file in files)
        {
            try
            {
                var doc = XDocument.Load(file);
                var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
                var actions = doc.Root?.Element(ns + "Actions");
                if (actions is null) { continue; }
                foreach (var exec in actions.Elements(ns + "Exec"))
                {
                    var cmd = exec.Element(ns + "Command")?.Value ?? "";
                    var args = exec.Element(ns + "Arguments")?.Value ?? "";
                    var full = (cmd + " " + args).Trim();
                    var lower = full.ToLowerInvariant();
                    foreach (var frag in SuspiciousFragments)
                    {
                        if (lower.Contains(frag, StringComparison.Ordinal))
                        {
                            var relative = Path.GetRelativePath(tasksRoot, file).Replace('\\', '/');
                            results.Add(new SuspiciousTask(relative, full,
                                $"Command matches suspicious fragment: '{frag.Trim()}'"));
                            goto nextFile; // one hit per task is enough
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Skip non-task file {File}", file);
            }
            nextFile: ;
        }
        return results;
    }
}
