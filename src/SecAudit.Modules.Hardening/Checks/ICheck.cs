using SecAudit.Core.Models;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Contract for a single hardening check. Checks are stateless, DI-registered, executed in
/// parallel by <see cref="HardeningModule"/>. Each check produces zero or one Finding
/// (a pass produces none; a fail produces exactly one Finding with enough evidence for
/// the admin to act).
/// </summary>
public interface ICheck
{
    CheckMetadata Metadata { get; }

    Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct);
}

public sealed record CheckMetadata(
    string Id,
    string Title,
    Severity DefaultSeverity,
    string Category,
    string CisReference);

public sealed class CheckContext
{
    public required string Asset { get; init; }
}
