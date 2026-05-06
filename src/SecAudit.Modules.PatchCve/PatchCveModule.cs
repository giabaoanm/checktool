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
    /// <summary>
    /// Key used to publish a <see cref="PatchSnapshot"/> into <c>ScanContext.SharedState</c>
    /// so the reporting layer (CLI / GUI dashboard) can render the "Tổng hợp bản vá" section
    /// regardless of whether any finding fired. Without this snapshot the formal report
    /// cannot answer "how many KBs are installed?" or "how stale is the CVE rule set?".
    /// </summary>
    public const string SharedSnapshotKey = "patch-cve.snapshot";

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
        DisplayName: "Bản vá & CVE",
        Description: "Kiểm tra CVE offline — đối chiếu các hotfix đã cài với danh sách bản vá quan trọng và cơ sở dữ liệu NVD.",
        Category: "Lỗ hổng bảo mật",
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
        int missingCriticalCount = 0;
        DateTimeOffset? cveLastSync = null;
        bool cveDbStale = true;
        int installedCount = 0;

        try
        {
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang thu thập hotfix đã cài", 10));
            var installedUpdates = _hotfix.CollectInstalledUpdates();
            installedCount = installedUpdates
                .Select(update => update.KbId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đọc thông tin hệ thống", 30));
            var inventory = context.GetShared<SystemInventory>(SystemInfoModule.SharedInventoryKey);

            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đánh giá các quy tắc CVE quan trọng", 50));
            var rules = FastPathRuleLoader.Load();
            int osBuild = TryParseBuild(inventory?.OperatingSystem.BuildNumber);

            foreach (var rule in rules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!AppliesToBuild(rule, osBuild))
                {
                    continue;
                }
                var coverage = PatchCoverageEvaluator.Evaluate(rule, installedUpdates);
                if (coverage.IsCovered)
                {
                    _logger.LogDebug(
                        "Fast-path CVE {CveId} covered by {CoverageKind}: {Reason}",
                        rule.Id,
                        coverage.Kind,
                        coverage.Reason);
                    continue;
                }
                missingCriticalCount++;
                var kbList = string.Join(" / ", rule.RequiredKbAny);
                var evidence = osBuild > 0
                    ? $"OS build {osBuild} nằm trong phạm vi ảnh hưởng; máy chưa cài bất kỳ KB vá nào ({kbList})."
                    : $"Không xác định được OS build; máy chưa cài KB vá nào ({kbList}).";

                findings.Add(Finding.Create(
                    id: rule.Id,
                    title: rule.Title,
                    severity: SeverityFromText(rule.Severity),
                    category: "Lỗ hổng bảo mật",
                    asset: context.MachineName,
                    evidence: evidence,
                    remediation: "Cài bản cập nhật Windows Cumulative Update mới nhất. Tham khảo: " + rule.Reference,
                    references: string.IsNullOrEmpty(rule.Reference) ? Array.Empty<string>() : new[] { rule.Reference },
                    cvss: rule.Cvss));
            }

            progress.Report(new ProgressUpdate(Metadata.Id, "Đang kiểm tra độ mới của CSDL CVE", 80));
            try
            {
                using var conn = _db.OpenOrCreate();
                cveLastSync = CveDatabase.GetLastSync(conn);
                if (cveLastSync is null)
                {
                    cveDbStale = true;
                    findings.Add(Finding.Create(
                        id: "CVE-DB-STALE-01",
                        title: "CSDL CVE nội bộ chưa từng được đồng bộ",
                        severity: Severity.Medium,
                        category: "Lỗ hổng bảo mật",
                        asset: context.MachineName,
                        evidence: "meta.last_sync rỗng — chỉ áp dụng được các quy tắc nội bộ (fast-path).",
                        remediation: "Dùng nút 'Cập nhật CSDL CVE' để tải feed NVD mới nhất (yêu cầu kết nối Internet)."));
                }
                else if ((DateTimeOffset.UtcNow - cveLastSync.Value).TotalDays > 30)
                {
                    cveDbStale = true;
                    findings.Add(Finding.Create(
                        id: "CVE-DB-STALE-02",
                        title: "CSDL CVE nội bộ đã quá 30 ngày chưa cập nhật",
                        severity: Severity.Low,
                        category: "Lỗ hổng bảo mật",
                        asset: context.MachineName,
                        evidence: $"last_sync={cveLastSync.Value:O}",
                        remediation: "Đồng bộ lại feed NVD."));
                }
                else
                {
                    cveDbStale = false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "CVE DB open failed");
            }

            // Publish snapshot for the reporting layer regardless of outcome — the
            // formal report's "Tổng hợp bản vá" section needs the counts even when
            // there are zero findings (clean-state evidence).
            context.SetShared(SharedSnapshotKey, new PatchSnapshot(
                InstalledKbCount: installedCount,
                MissingCriticalRuleCount: missingCriticalCount,
                CveDbLastSync: cveLastSync,
                CveDbStale: cveDbStale));

            progress.Report(new ProgressUpdate(Metadata.Id, "Hoàn tất", 100));

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
                FailureReason = "Đã bị hủy",
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

/// <summary>
/// Cross-module snapshot published into <see cref="ScanContext"/> shared state
/// so the reporting layer can render baseline patch facts without re-querying
/// WMI. Lives next to the module so callers don't pull in Reporting types.
/// </summary>
public sealed record PatchSnapshot(
    int InstalledKbCount,
    int MissingCriticalRuleCount,
    DateTimeOffset? CveDbLastSync,
    bool CveDbStale);
