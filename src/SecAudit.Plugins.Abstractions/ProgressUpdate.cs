namespace SecAudit.Plugins.Abstractions;

public sealed record ProgressUpdate(
    string ModuleId,
    string Stage,
    int PercentComplete,
    string? Message = null);
