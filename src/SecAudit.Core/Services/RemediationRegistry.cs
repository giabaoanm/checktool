using SecAudit.Plugins.Abstractions;

namespace SecAudit.Core.Services;

/// <summary>
/// Resolves Finding IDs to <see cref="IRemediationAction"/> instances.
///
/// All registered actions are injected as <c>IEnumerable&lt;IRemediationAction&gt;</c>;
/// the registry indexes them by <see cref="IRemediationAction.FindingId"/>. UI code asks
/// "is this finding fixable?" via <see cref="TryGet"/> and only renders the "Vá ngay"
/// button when an action exists.
///
/// Duplicate FindingIds throw at construction — they're a configuration bug.
/// </summary>
public sealed class RemediationRegistry
{
    private readonly Dictionary<string, IRemediationAction> _byId;

    public RemediationRegistry(IEnumerable<IRemediationAction> actions)
    {
        ArgumentNullException.ThrowIfNull(actions);
        _byId = new Dictionary<string, IRemediationAction>(StringComparer.OrdinalIgnoreCase);
        foreach (var action in actions)
        {
            if (!_byId.TryAdd(action.FindingId, action))
            {
                throw new InvalidOperationException(
                    $"Duplicate IRemediationAction registered for FindingId='{action.FindingId}'. " +
                    $"Existing: {_byId[action.FindingId].GetType().Name}, new: {action.GetType().Name}.");
            }
        }
    }

    /// <summary>True if any action is registered for the given Finding ID.</summary>
    public bool CanFix(string findingId) => _byId.ContainsKey(findingId);

    /// <summary>Get the action for a Finding ID, or null if none registered.</summary>
    public IRemediationAction? TryGet(string findingId)
        => _byId.TryGetValue(findingId, out var action) ? action : null;

    /// <summary>Snapshot of all currently-registered actions, ordered by FindingId.</summary>
    public IReadOnlyList<IRemediationAction> All
        => _byId.Values.OrderBy(a => a.FindingId, StringComparer.Ordinal).ToList();
}
