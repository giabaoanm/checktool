using SecAudit.Reporting.Models;

namespace SecAudit.Reporting;

/// <summary>
/// Contract for one report format. Writers receive a fully-built ReportData and
/// emit a single self-contained file.
/// </summary>
public interface IReportWriter
{
    /// <summary>File extension WITHOUT the leading dot — e.g. "html", "pdf", "json".</summary>
    string Extension { get; }
    string DisplayName { get; }
    Task WriteAsync(ReportData data, string outputPath, CancellationToken ct);
}
