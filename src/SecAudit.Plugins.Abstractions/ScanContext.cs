namespace SecAudit.Plugins.Abstractions;

/// <summary>
/// Per-run context handed to every module. Carries options, target asset identity, and a place
/// for shared state (e.g., software inventory produced by SystemInfo and consumed by PatchCve).
/// </summary>
public sealed class ScanContext
{
    public required string MachineName { get; init; }
    public required string CurrentUserSid { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required IReadOnlyDictionary<string, string> Options { get; init; }

    private readonly Dictionary<string, object> _sharedState = new(StringComparer.Ordinal);

    public void SetShared<T>(string key, T value) where T : notnull => _sharedState[key] = value;

    public T? GetShared<T>(string key) where T : class
        => _sharedState.TryGetValue(key, out var v) ? v as T : null;

    public bool TryGetOption(string key, out string value)
    {
        if (Options.TryGetValue(key, out var v) && v is not null)
        {
            value = v;
            return true;
        }
        value = string.Empty;
        return false;
    }
}
