using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Modules.RemoteAccess.Detectors;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.RemoteAccess;

/// <summary>
/// Iteration 6 — defensive detection of remote-access tooling and persistence beacons
/// based purely on registry / WMI signals. Findings are interpretive guidance for the
/// SOC operator; we never modify or remove anything we detect.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RemoteAccessModule : IAuditModule
{
    private static readonly string[] RefRat =
    {
        "https://attack.mitre.org/techniques/T1219/"
    };
    private static readonly string[] RefRunKeys =
    {
        "https://attack.mitre.org/techniques/T1547/001/"
    };
    private static readonly string[] RefWmiSub =
    {
        "https://attack.mitre.org/techniques/T1546/003/"
    };
    private static readonly string[] RefServices =
    {
        "https://attack.mitre.org/techniques/T1543/003/"
    };
    private static readonly string[] RefScheduledTask =
    {
        "https://attack.mitre.org/techniques/T1053/005/"
    };

    private readonly PersistenceDetector _persistence;
    private readonly WmiPersistenceDetector _wmi;
    private readonly ServicesHiveDetector _services;
    private readonly ScheduledTasksXmlDetector _tasks;
    private readonly IOfflineTarget _target;
    private readonly ILogger<RemoteAccessModule> _logger;

    public RemoteAccessModule(
        PersistenceDetector persistence,
        WmiPersistenceDetector wmi,
        ServicesHiveDetector services,
        ScheduledTasksXmlDetector tasks,
        IOfflineTarget target,
        ILogger<RemoteAccessModule> logger)
    {
        _persistence = persistence;
        _wmi = wmi;
        _services = services;
        _tasks = tasks;
        _target = target;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "remote-access",
        DisplayName: "Remote Access & Persistence",
        Description: "Registry/WMI signals for installed remote-access tools and autostart/WMI persistence.",
        Category: "Threat Surface",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: false,
        DisplayOrder: 50);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();
        var asset = context.MachineName;

        try
        {
            // 1) Remote-access tools
            progress.Report(new ProgressUpdate(Metadata.Id, "Scanning installed software for remote-access tools", 10));
            var inventory = context.GetShared<SystemInventory>(SystemInfoModule.SharedInventoryKey);
            if (inventory is not null)
            {
                var tools = RemoteAccessToolDetector.Detect(inventory.Software);
                foreach (var t in tools)
                {
                    findings.Add(Finding.Create(
                        id: $"RA-TOOL-{Sanitize(t.ProductName)}",
                        title: $"Remote-access tool installed: {t.ProductName}",
                        severity: ParseSev(t.Severity),
                        category: "Remote Access",
                        asset: asset,
                        evidence: $"Vendor={t.Vendor}; reason={t.Why}",
                        remediation: "Confirm with the user/admin that this tool is required. If not, uninstall via Settings → Apps. If required, restrict inbound access at the firewall and require MFA on the vendor portal.",
                        references: RefRat));
                }
            }
            else
            {
                _logger.LogWarning("SystemInfo inventory not available — RAT detection skipped");
                if (!_target.IsLive)
                {
                    findings.Add(Finding.Create(
                        id: "RA-TOOL-OFFLINE",
                        title: "Installed-software scan skipped (offline mode)",
                        severity: Severity.Info,
                        category: "Remote Access",
                        asset: asset,
                        evidence: "The SystemInfo module is disabled in --offline mode because it depends on WMI. Enumerate Uninstall keys manually from HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall on the mounted volume if you need this list.",
                        remediation: "Re-run live on the target host once boot is safe."));
                }
            }

            // 2) Autostart persistence
            progress.Report(new ProgressUpdate(Metadata.Id, "Inspecting Run/RunOnce autostart entries", 50));
            var autoruns = _persistence.Detect();
            foreach (var entry in autoruns.Where(e => e.Suspicious))
            {
                findings.Add(Finding.Create(
                    id: $"RA-RUN-{Sanitize(entry.Hive + "-" + entry.Name)}",
                    title: $"Suspicious autostart: {entry.Name}",
                    severity: Severity.High,
                    category: "Persistence",
                    asset: asset,
                    evidence: $"{entry.Hive}\\{entry.Location}\\{entry.Name} = {entry.Command}  ({entry.Reason})",
                    remediation: "Validate the binary signature and origin. If untrusted, delete the registry value and remove the file. Capture a copy first for IR.",
                    references: RefRunKeys));
            }
            // Always emit one Info row summarising autostart inventory size, useful for triage.
            findings.Add(Finding.Create(
                id: "RA-RUN-SUMMARY",
                title: $"Autostart entries inventoried ({autoruns.Count} total, {autoruns.Count(e => e.Suspicious)} suspicious)",
                severity: Severity.Info,
                category: "Persistence",
                asset: asset,
                evidence: string.Join(" | ",
                    autoruns.Take(10).Select(e => $"{e.Hive}:{e.Name}")),
                remediation: "Review the complete list in the JSON export."));

            // 3) Services hive — auto-start services with suspicious ImagePath
            progress.Report(new ProgressUpdate(Metadata.Id, "Inspecting Services hive for auto-start persistence", 60));
            var svcHits = _services.Detect();
            foreach (var svc in svcHits)
            {
                findings.Add(Finding.Create(
                    id: $"RA-SVC-{Sanitize(svc.Name)}",
                    title: $"Suspicious auto-start service: {svc.Name}",
                    severity: Severity.High,
                    category: "Persistence",
                    asset: asset,
                    evidence: $"Name={svc.Name}; Start={svc.Start}; ImagePath={svc.ImagePath}; {svc.Reason}",
                    remediation: "Verify service origin (sc qc <name>, Get-AuthenticodeSignature). If untrusted, capture a copy then 'sc stop && sc delete'. Inspect the binary for additional persistence.",
                    references: RefServices));
            }

            // 4) Scheduled tasks XML — encoded PowerShell / LOLBin / user-writable payloads
            progress.Report(new ProgressUpdate(Metadata.Id, "Scanning scheduled-task XML definitions", 75));
            var taskHits = _tasks.Detect();
            foreach (var t in taskHits)
            {
                findings.Add(Finding.Create(
                    id: $"RA-TASK-{Sanitize(t.Path)}",
                    title: $"Suspicious scheduled task: {t.Path}",
                    severity: Severity.High,
                    category: "Persistence",
                    asset: asset,
                    evidence: $"Path=\\Microsoft\\...\\{t.Path}; Command={Truncate(t.Command, 300)}; {t.Reason}",
                    remediation: "Export the task XML for evidence, then 'schtasks /Delete /TN \"<path>\" /F' (live) or delete the XML file (offline). Investigate the binary.",
                    references: RefScheduledTask));
            }

            // 5) WMI permanent event subscriptions — live mode only
            if (_target.IsLive)
            {
                progress.Report(new ProgressUpdate(Metadata.Id, "Querying WMI permanent event subscriptions", 90));
                var wmiHits = _wmi.Detect();
                foreach (var item in wmiHits)
                {
                    findings.Add(Finding.Create(
                        id: $"RA-WMI-{Sanitize(item.Class + "-" + item.Name)}",
                        title: $"WMI {item.Class}: {item.Name}",
                        severity: Severity.High,
                        category: "Persistence",
                        asset: asset,
                        evidence: item.Detail,
                        remediation: "Default Windows installs ship 0–2 well-known entries here. Anything else should be triaged. Use 'Get-WmiObject -Namespace root\\subscription -Class __EventFilter' (etc.) to enumerate, then 'Remove-WmiObject' after capturing evidence.",
                        references: RefWmiSub));
                }
            }
            else
            {
                findings.Add(Finding.Create(
                    id: "RA-WMI-OFFLINE",
                    title: "WMI event-subscription scan skipped (offline mode)",
                    severity: Severity.Info,
                    category: "Persistence",
                    asset: asset,
                    evidence: "WMI root\\subscription cannot be queried on a mounted volume — the repository lives in a proprietary binary format. Re-run live on the target host to catch this class of persistence (MITRE T1546.003).",
                    remediation: "Boot the host normally once triage permits, then run SecAudit in live mode."));
            }

            progress.Report(new ProgressUpdate(Metadata.Id, "Done", 100));
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RemoteAccessModule failed");
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = ex.Message,
                Findings = findings
            });
        }
    }

    private static Severity ParseSev(string s) => s switch
    {
        "Critical" => Severity.Critical,
        "High" => Severity.High,
        "Medium" => Severity.Medium,
        "Low" => Severity.Low,
        _ => Severity.Info
    };

    private static string Sanitize(string s)
    {
        var chars = s.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_').ToArray();
        var result = new string(chars);
        return result.Length > 40 ? result[..40] : result;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
