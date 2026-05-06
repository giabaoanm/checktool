using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.WebIncident;

public sealed record WebIncidentSettings
{
    public IReadOnlyList<string> Targets { get; init; } = Array.Empty<string>();
    public string EvidenceRoot { get; init; } = string.Empty;
    public string ServerEvidencePath { get; init; } = string.Empty;
    public string WebRootPath { get; init; } = string.Empty;
    public string BaselineManifestPath { get; init; } = string.Empty;
    public string ExpectedContentSha256 { get; init; } = string.Empty;
    public int TimeoutSeconds { get; init; } = 15;
    public int MaxBodyBytes { get; init; } = 5 * 1024 * 1024;
    public int SlowResponseThresholdMs { get; init; } = 8000;
    public int MaxServerEvidenceFiles { get; init; } = 5000;
    public bool ProbePlainHttp { get; init; } = true;
    public bool CaptureHttpBody { get; init; }
    public bool EnableLiveWebProbe { get; init; }
    public bool SafeLiveContentAnalysis { get; init; } = true;
    public int MaxLiveLinkedResources { get; init; } = 20;
    public IReadOnlyList<string> AllowedExternalHosts { get; init; } = Array.Empty<string>();
}

public sealed record WebIncidentProgress(
    string SessionId,
    string Message,
    int PercentComplete);

public sealed record WebIncidentEvidenceFile(
    string Name,
    string LocalPath,
    string Kind,
    long SizeBytes,
    string Sha256,
    DateTimeOffset CollectedAt);

public sealed record WebDnsObservation(
    string Host,
    IReadOnlyList<string> Addresses,
    string? Error);

public sealed record WebTlsObservation(
    string Host,
    int Port,
    string Subject,
    string Issuer,
    string Thumbprint,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    string PolicyErrors,
    string? Error);

public sealed record WebHttpObservation(
    string Url,
    int Hop,
    int? StatusCode,
    string ReasonPhrase,
    long ElapsedMs,
    string? RedirectLocation,
    string ContentType,
    long BodyBytes,
    string BodySha256,
    string? Error,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Headers);

public sealed record WebContentSignals(
    string? Title,
    bool DefacementMarker,
    bool RansomOrEncryptionMarker,
    bool ExternalRedirectOrFrame,
    bool SuspiciousScriptOrObfuscation,
    bool CredentialOrPaymentPhishingMarker,
    bool HiddenIframeOrSkimmerMarker,
    IReadOnlyList<string> MatchedTerms,
    IReadOnlyList<string> ExternalHosts,
    IReadOnlyList<string> SuspiciousPatterns,
    IReadOnlyList<WebLinkedResource> LinkedResources);

public sealed record WebLinkedResource(
    string Url,
    string Kind,
    bool IsExternal);

public sealed record WebLiveResourceObservation(
    string Url,
    string Kind,
    bool IsExternal,
    int? StatusCode,
    string ContentType,
    long BodyBytes,
    string BodySha256,
    string Classification,
    IReadOnlyList<string> Signals,
    string? Error);

public sealed record WebAttackTimelineEvent(
    DateTimeOffset? Timestamp,
    string SourceIp,
    string Method,
    string Path,
    int? StatusCode,
    string UserAgent,
    string Rule,
    string SourceFile,
    string Raw);

public sealed record WebRootFileRecord(
    string RelativePath,
    long SizeBytes,
    DateTimeOffset LastWriteUtc,
    string Sha256,
    string Classification);

public sealed record WebServerEvidenceSummary(
    string? SourcePath,
    string? WebRootPath,
    string? BaselineManifestPath,
    IReadOnlyList<WebAttackTimelineEvent> Timeline,
    IReadOnlyList<WebRootFileRecord> WebRootManifest,
    IReadOnlyList<WebRootFileRecord> SuspiciousFiles);

public sealed record WebIncidentResult(
    string SessionId,
    string Target,
    string NormalizedUrl,
    string EvidenceRoot,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    WebDnsObservation? Dns,
    WebTlsObservation? Tls,
    IReadOnlyList<WebHttpObservation> Http,
    WebContentSignals? ContentSignals,
    IReadOnlyList<WebLiveResourceObservation> LiveResources,
    WebServerEvidenceSummary? ServerEvidence,
    IReadOnlyList<WebIncidentEvidenceFile> Manifest,
    IReadOnlyList<Finding> Findings);
