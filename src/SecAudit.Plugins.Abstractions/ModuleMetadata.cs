namespace SecAudit.Plugins.Abstractions;

/// <summary>
/// Static descriptor for an audit module. Used by the shell for navigation, ordering, and gating.
/// </summary>
public sealed record ModuleMetadata(
    string Id,
    string DisplayName,
    string Description,
    string Category,
    string Version,
    bool RequiresAdministrator,
    bool IsSensitive,
    int DisplayOrder);
