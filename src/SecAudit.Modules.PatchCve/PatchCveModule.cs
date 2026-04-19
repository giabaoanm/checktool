using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Cve.Pipeline;
using SecAudit.Cve.Pipeline.Models;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.PatchCve;

/// <summary>
/// Iteration 3 module. Combines:
///  1. Embedded fast-path rules (MS17-010, PrintNightmare, SMBGhost, Follina, BlueKeep,
///     PetitPotam) — an installed KB short-circuits the finding.
///  2. The offline NVD SQLite DB for version-range matching on third-party software
///     collected by <see cref="SystemInfoModule"/>. (v1 only opens + shows last-sync; the
///     full matcher lands once a seeded DB is shipped.)
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PatchCveModule : IAuditModule
{
    private readonly HotfixInventory _hotfix;
    private readonly CveDatabase _db;
    private readonly ILogger<PatchCveModule> _logger;

    public PatchCveModule(
        HotfixInventory hotfix,
        CveDatabase db,
        ILogger<PatchCveModule> logger)
    {
        _hotfix = hotfix;
        _db = db;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "patch-cve",
        DisplayName: "Patch & CVE",
        Description: "Offline CVE audit — installed hotfixes vs. critical-patch rules and optional NVD database.",
        Category: "Vulnerabilities",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: false,
        DisplayOrder: 30);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();

        try
        {
            progress.Report(new ProgressUpdate(Metadata.Id, "Collecting installed hotfixes", 10));
            var installedKbs = _hotfix.CollectInstalledKbs();

            progress.Report(new ProgressUpdate(Metadata.Id, "Reading inventory", 30));
            var inventory = context.GetShared<SystemInventory>(SystemInfoModule.SharedInventoryKey);

            progress.Report(new ProgressUpdate(Metadata.Id, "Evaluating fast-path rules", 50));
            var rules = FastPathRuleLoader.Load();
            int osBuild = TryParseBuild(inventory?.OperatingSystem.BuildNumber);

            foreach (var rule in rules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!AppliesToBuild(rule, osBuild))
                {
                    continue;
                }
                var covered = rule.RequiredKbAny.Any(kb => installedKbs.Contains(kb));
                if (covered)
                {
                    continue;
                }
                var kbList = string.Join(" / ", rule.RequiredKbAny);
                var evidence = osBuild > 0
                    ? $"OS build {osBuild} matches vulnerable range; none of the fixing KBs installed ({kbList})."
                    : $"OS build unknown; none of the fixing KBs installed ({kbList}).";

                findings.Add(Finding.Create(
                    id: rule.Id,
                    title: rule.Title,
                    severity: SeverityFromText(rule.Severity),
                    category: "Vulnerabilities",
                    asset: context.MachineName,
                    evidence: evidence,
                    remediation: "Install the latest Windows cumulative update. Reference: " + rule.Reference,
                    references: string.IsNullOrEmpty(rule.Reference) ? Array.Empty<string>() : new[] { rule.Reference },
                    cvss: rule.Cvss));
            }

            progress.Report(new ProgressUpdate(Metadata.Id, "Checking CVE database freshness", 80));
            try
            {
                using var conn = _db.OpenOrCreate();
                var lastSync = CveDatabase.GetLastSync(conn);
                if (lastSync is null)
                {
                    findings.Add(Finding.Create(
                        id: "CVE-DB-STALE-01",
                        title: "Local CVE database has never been synchronized",
                        severity: Severity.Medium,
                        category: "Vulnerabilities",
                        asset: context.MachineName,
                        evidence: "meta.last_sync is empty — only fast-path rules were applied.",
                        remediation: "Use 'Update CVE database' to pull the latest NVD feed (internet required)."));
                }
                else if ((DateTimeOffset.UtcNow - lastSync.Value).TotalDays > 30)
                {
                    findings.Add(Finding.Create(
                        id: "CVE-DB-STALE-02",
                        title: "Local CVE database is more than 30 days old",
                        severity: Severity.Low,
                        category: "Vulnerabilities",
                        asset: context.MachineName,
                        evidence: $"last_sync={lastSync.Value:O}",
                        remediation: "Re-sync the NVD feed."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "CVE DB open failed");
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
        catch (OperationCanceledException)
        {
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = "Cancelled",
                Findings = findings
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PatchCveModule failed");
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

    private static bool AppliesToBuild(FastPathRule rule, int build)
    {
        if (build <= 0)
        {
            return true; // unknown build → be cautious, evaluate rule
        }
        if (rule.AppliesToOsBuildsBelow is int below && build >= below)
        {
            return false;
        }
        if (rule.AppliesToOsBuildsAbove is int above && build <= above)
        {
            return false;
        }
        return true;
    }

    private static int TryParseBuild(string? s)
        => int.TryParse(s, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : 0;

    private static Severity SeverityFromText(string t) => t.ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "HIGH" => Severity.High,
        "MEDIUM" => Severity.Medium,
        "LOW" => Severity.Low,
        _ => Severity.Medium
    };
}
