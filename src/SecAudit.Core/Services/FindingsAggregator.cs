using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Core.Services;

/// <summary>
/// Collects ModuleResults from many modules into a unified list of Findings, indexed by module.
/// </summary>
public sealed class FindingsAggregator
{
    private readonly Dictionary<string, List<Finding>> _byModule = new(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, IReadOnlyList<Finding>> ByModule
        => _byModule.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<Finding>)kv.Value);

    public IReadOnlyList<Finding> All => _byModule.Values.SelectMany(x => x).ToList();

    public void Add(ModuleResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var bucket = _byModule.TryGetValue(result.ModuleId, out var existing)
            ? existing
            : (_byModule[result.ModuleId] = new List<Finding>());

        foreach (var raw in result.Findings)
        {
            if (raw is Finding f)
            {
                bucket.Add(f);
            }
        }
    }
}
