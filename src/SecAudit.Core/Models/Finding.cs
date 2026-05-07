namespace SecAudit.Core.Models;

/// <summary>
/// Single audit finding. Immutable. Produced by modules, consumed by aggregator + reports.
/// </summary>
/// <remarks>
/// <see cref="AttackTechniqueIds"/> is an <c>init</c>-only property (not a positional
/// record arg) so adding it does not break the 170+ existing <c>Finding.Create</c>
/// call sites. Modules that want to publish ATT&amp;CK mapping pass it through the
/// <c>attackTechniques</c> parameter on <see cref="Create"/>.
/// </remarks>
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
    /// <summary>
    /// MITRE ATT&amp;CK technique IDs (e.g. <c>T1003.001</c>, <c>T1547.001</c>) that
    /// classify the adversary behaviour this finding detects. Empty when the finding
    /// is descriptive (system inventory, license info) rather than detection-grade.
    /// SOC report writers join this with <c>SecAudit.Core.Mitre.MitreAttackCatalog</c>
    /// to render human-readable technique names.
    /// </summary>
    public IReadOnlyList<string> AttackTechniqueIds { get; init; } = Array.Empty<string>();

    public static Finding Create(
        string id,
        string title,
        Severity severity,
        string category,
        string asset,
        string evidence,
        string remediation,
        IReadOnlyList<string>? references = null,
        double? cvss = null,
        IReadOnlyList<string>? attackTechniques = null)
        => new(id, title, severity, cvss, category, asset, evidence, remediation,
            references ?? Array.Empty<string>(), DateTimeOffset.UtcNow)
        {
            AttackTechniqueIds = attackTechniques ?? Array.Empty<string>()
        };
}
