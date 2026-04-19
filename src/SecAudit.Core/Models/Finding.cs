namespace SecAudit.Core.Models;

/// <summary>
/// Single audit finding. Immutable. Produced by modules, consumed by aggregator + reports.
/// </summary>
public sealed record Finding(
    string Id,
    string Title,
    Severity Severity,
    double? CvssScore,
    string Category,
    string Asset,
    string Evidence,
    string Remediation,
    IReadOnlyList<string> References,
    DateTimeOffset DetectedAt)
{
    public static Finding Create(
        string id,
        string title,
        Severity severity,
        string category,
        string asset,
        string evidence,
        string remediation,
        IReadOnlyList<string>? references = null,
        double? cvss = null)
        => new(id, title, severity, cvss, category, asset, evidence, remediation,
            references ?? Array.Empty<string>(), DateTimeOffset.UtcNow);
}
