using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Reporting.Models;

namespace SecAudit.Reporting;

/// <summary>
/// Façade for the UI / CLI: takes a FindingsAggregator + risk score + caller-supplied
/// device profile and writes one or more formats to a chosen folder. Returns the list
/// of written file paths.
///
/// The caller (App or CLI) is responsible for building <see cref="DeviceProfile"/>
/// because it requires reading SystemInventory + NetworkInterface — both of which
/// are Windows-specific concerns we don't want to leak into the Reporting layer.
/// </summary>
public sealed class ReportService
{
    private readonly IEnumerable<IReportWriter> _writers;
    private readonly RemediationRegistry _remediations;
    private readonly ILogger<ReportService> _logger;

    public ReportService(
        IEnumerable<IReportWriter> writers,
        RemediationRegistry remediations,
        ILogger<ReportService> logger)
    {
        _writers = writers;
        _remediations = remediations;
        _logger = logger;
    }

    public IReadOnlyList<IReportWriter> Writers => _writers.ToArray();

    /// <summary>
    /// Build a complete <see cref="ReportData"/>. Recommendations are derived from
    /// findings whose ID does not resolve in the remediation registry AND that have
    /// not already been auto-applied — i.e. things the user must fix manually.
    /// </summary>
    public ReportData BuildData(
        FindingsAggregator aggregator,
        RiskScore score,
        string assetName,
        DeviceProfile device,
        IReadOnlyList<AppliedAction> appliedActions,
        ReportSettings metadata)
    {
        ArgumentNullException.ThrowIfNull(aggregator);
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(appliedActions);
        ArgumentNullException.ThrowIfNull(metadata);

        var byModule = aggregator.ByModule;
        var counts = aggregator.All
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var appliedSucceededIds = appliedActions
            .Where(a => a.Succeeded)
            .Select(a => a.FindingId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Recommendations: every finding that wasn't auto-fixed (either no action exists
        // or the user chose not to apply it). Skip Info severity to keep the section actionable.
        var recommendations = aggregator.All
            .Where(f => f.Severity != Severity.Info)
            .Where(f => !appliedSucceededIds.Contains(f.Id))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .Select(f => new Recommendation(
                FindingId: f.Id,
                Title: f.Title,
                Severity: f.Severity.ToString(),
                Guidance: BuildGuidance(f)))
            .ToList();

        return new ReportData(
            AssetName: assetName,
            GeneratedAt: DateTimeOffset.Now,
            Score: score,
            ByModule: byModule,
            SeverityCounts: counts,
            Device: device,
            AppliedActions: appliedActions,
            Recommendations: recommendations,
            Metadata: metadata);
    }

    /// <summary>
    /// Compose the recommendation text. If we have a registered auto-fix the user
    /// can run it from the dashboard; otherwise we surface the finding's existing
    /// Remediation field as the manual guidance.
    /// </summary>
    private string BuildGuidance(Finding f)
    {
        var action = _remediations.TryGet(f.Id);
        if (action is not null)
        {
            return $"Có thể vá tự động bằng nút \"Vá ngay\" trong Dashboard ({action.Title}). " +
                   $"Hoặc thực hiện thủ công: {f.Remediation}";
        }
        return string.IsNullOrWhiteSpace(f.Remediation)
            ? "Tham khảo tài liệu Microsoft / CIS Benchmark cho khuyến nghị cụ thể."
            : f.Remediation;
    }

    public async Task<IReadOnlyList<string>> WriteAllAsync(
        ReportData data,
        string outputFolder,
        CancellationToken ct)
    {
        Directory.CreateDirectory(outputFolder);
        var stamp = data.GeneratedAt.ToString("yyyyMMdd-HHmmss");
        var written = new List<string>();
        foreach (var writer in _writers)
        {
            var path = Path.Combine(outputFolder, $"secaudit-{data.AssetName}-{stamp}.{writer.Extension}");
            try
            {
                await writer.WriteAsync(data, path, ct).ConfigureAwait(false);
                _logger.LogInformation("Wrote {Format} report to {Path}", writer.DisplayName, path);
                written.Add(path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write {Format} report", writer.DisplayName);
            }
        }
        return written;
    }
}
