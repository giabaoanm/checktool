namespace SecAudit.Cve.Pipeline.Models;

public sealed record CveRecord(
    string CveId,
    DateTimeOffset Published,
    DateTimeOffset LastModified,
    double? CvssV3Score,
    string? CvssV3Vector,
    string? Severity,
    string Description,
    IReadOnlyList<CpeMatch> CpeMatches,
    IReadOnlyList<string> References);

public sealed record CpeMatch(
    string Vendor,
    string Product,
    string? VersionStartIncluding,
    string? VersionStartExcluding,
    string? VersionEndIncluding,
    string? VersionEndExcluding);

public sealed record FastPathRule(
    string Id,
    string Title,
    double Cvss,
    string Severity,
    IReadOnlyList<string> RequiredKbAny,
    int? AppliesToOsBuildsBelow,
    int? AppliesToOsBuildsAbove,
    string Reference);
