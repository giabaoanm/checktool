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
        ReportSettings metadata,
        LicenseSummary? license = null,
        PatchSummary? patch = null,
        ScanScope? scope = null)
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
            License: license,
            Patch: patch,
            Scope: scope,
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
        // Resolve to a writable folder. The requested path is tried first; if it can't
        // be created or is not writable (read-only USB, locked-down safe-mode profile,
        // ACL denial) we fall back through Desktop → Documents → %TEMP% so the SOC
        // operator never ends up with "scanned but couldn't save" — that scenario was
        // observed at Sơn La when running SecAudit from Safe Mode.
        outputFolder = ResolveWritableFolder(outputFolder);

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

    /// <summary>
    /// Try the requested folder, then Desktop, Documents, and finally %TEMP%. The first
    /// folder where we can both <c>CreateDirectory</c> and write+delete a probe file
    /// wins. If everything fails (extraordinarily — even %TEMP% blocked) we fall back
    /// to the current directory unconditionally and let the file-write fail per
    /// individual writer with a logged error.
    /// </summary>
    private string ResolveWritableFolder(string requested)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(requested)) { candidates.Add(requested); }
        try
        {
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "BAO CAO SecAudit"));
        }
        catch { }
        try
        {
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "SecAudit Reports"));
        }
        catch { }
        try { candidates.Add(Path.Combine(Path.GetTempPath(), "SecAudit Reports")); } catch { }
        candidates.Add(Environment.CurrentDirectory);

        foreach (var c in candidates)
        {
            if (TryProbeWritable(c, out var resolved))
            {
                if (!string.Equals(resolved, requested, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "Output folder '{Requested}' không ghi được; chuyển sang fallback '{Resolved}'",
                        requested, resolved);
                }
                return resolved;
            }
        }
        // Last-resort: unmodified requested path; file-write will throw and be logged.
        return requested;
    }

    private bool TryProbeWritable(string folder, out string resolved)
    {
        resolved = folder;
        try
        {
            Directory.CreateDirectory(folder);
            var probe = Path.Combine(folder, ".secaudit-write-probe-" + Guid.NewGuid().ToString("N")[..8]);
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Probe write failed for {Folder}", folder);
            return false;
        }
    }
}
