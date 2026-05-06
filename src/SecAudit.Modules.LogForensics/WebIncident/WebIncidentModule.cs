using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics.WebIncident;

public sealed class WebIncidentModule : IAuditModule
{
    public const string OptionKey = "web-incident.settings";
    public const string SharedResultsKey = "web-incident.results";

    private readonly WebIncidentEvidenceCollector _collector;
    private readonly ILogger<WebIncidentModule> _logger;

    public WebIncidentModule(
        WebIncidentEvidenceCollector collector,
        ILogger<WebIncidentModule> logger)
    {
        _collector = collector;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "web-incident",
        DisplayName: "Ứng cứu sự cố website/domain",
        Description: "Phân tích evidence/log/webroot website; live DNS/TLS/HTTP probe là tùy chọn nâng cao khi cần.",
        Category: "Incident Response",
        Version: "1.0.0",
        RequiresAdministrator: false,
        IsSensitive: true,
        DisplayOrder: 65);

    public async Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(progress);

        var started = DateTimeOffset.UtcNow;
        if (!context.TryGetOption(OptionKey, out var json) || string.IsNullOrWhiteSpace(json))
        {
            return Done(started, Array.Empty<object>(), null);
        }

        WebIncidentSettings settings;
        try
        {
            settings = JsonSerializer.Deserialize<WebIncidentSettings>(json) ?? new WebIncidentSettings();
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Invalid web incident settings");
            return Done(started, Array.Empty<object>(), "Cấu hình web incident không hợp lệ.", succeeded: false);
        }

        var targets = settings.Targets
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var hasEvidenceInput = !string.IsNullOrWhiteSpace(settings.ServerEvidencePath)
            || !string.IsNullOrWhiteSpace(settings.WebRootPath)
            || !string.IsNullOrWhiteSpace(settings.BaselineManifestPath);
        if (targets.Length == 0)
        {
            if (!hasEvidenceInput)
            {
                return Done(started, Array.Empty<object>(), null);
            }
            targets = new[] { string.Empty };
        }

        var findings = new List<object>();
        var results = new List<WebIncidentResult>();
        for (var i = 0; i < targets.Length; i++)
        {
            var target = targets[i];
            var basePercent = (int)(i * 100.0 / targets.Length);
            try
            {
                var nested = new Progress<WebIncidentProgress>(p =>
                {
                    var pct = Math.Min(99, basePercent + (int)(p.PercentComplete / (double)targets.Length));
                    progress.Report(new ProgressUpdate(Metadata.Id, p.Message, pct, target));
                });
                var result = await _collector.CollectAsync(target, settings, nested, cancellationToken)
                    .ConfigureAwait(false);
                results.Add(result);
                findings.AddRange(result.Findings);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Web incident collection failed for {Target}", target);
                findings.Add(Finding.Create(
                    "WEB-COLLECT-FAILED",
                    "Không thu thập được bằng chứng website",
                    Severity.Medium,
                    "web-incident.evidence",
                    target,
                    ex.Message,
                    "Kiểm tra lại URL/domain, kết nối mạng, DNS và quyền ghi thư mục evidence; chạy lại collection trong khung thời gian sự cố."));
            }
        }

        context.SetShared(SharedResultsKey, results);
        progress.Report(new ProgressUpdate(Metadata.Id, "Hoàn tất web incident collection", 100));
        return Done(started, findings, null);
    }

    private ModuleResult Done(
        DateTimeOffset started,
        IReadOnlyList<object> findings,
        string? reason,
        bool succeeded = true)
        => new()
        {
            ModuleId = Metadata.Id,
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            Succeeded = succeeded,
            FailureReason = reason,
            Findings = findings
        };
}
