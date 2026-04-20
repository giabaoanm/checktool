namespace SecAudit.Plugins.Abstractions;

/// <summary>
/// Auto-remediation action bound to a specific Finding ID. Modules supply one per fix they
/// know how to apply; the UI surfaces a "Vá ngay" button only for findings that resolve
/// against the registry.
///
/// Contract:
/// - <see cref="FindingId"/> matches the Finding.Id exactly (one action per finding).
/// - <see cref="ApplyAsync"/> must be idempotent: re-running on an already-fixed system
///   should return Succeeded=true with a "no-op" message rather than throwing.
/// - Implementations MUST NOT prompt the user. UI handles confirmation/elevation upstream.
/// </summary>
public interface IRemediationAction
{
    /// <summary>The Finding.Id this action remediates (e.g. "HD-AUTORUN-01").</summary>
    string FindingId { get; }

    /// <summary>Short Vietnamese label shown in confirm dialogs (e.g. "Bật RDP NLA").</summary>
    string Title { get; }

    /// <summary>One-paragraph description of what the action will change.</summary>
    string Description { get; }

    /// <summary>True if a system reboot is required for the change to take effect.</summary>
    bool RequiresReboot { get; }

    /// <summary>True if the action requires Administrator privileges (almost always true).</summary>
    bool RequiresAdmin { get; }

    Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Outcome of a single <see cref="IRemediationAction.ApplyAsync"/> invocation.
/// </summary>
/// <param name="Succeeded">True if the change was applied (or already in the desired state).</param>
/// <param name="Message">Human-readable Vietnamese summary shown to the operator and written to the audit log.</param>
/// <param name="RebootRequired">True if a reboot is now pending. May be true even when the action itself didn't need one (e.g. another pending change).</param>
public sealed record RemediationResult(bool Succeeded, string Message, bool RebootRequired);
