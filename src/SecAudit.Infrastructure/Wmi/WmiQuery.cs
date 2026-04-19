using System.Management;
using System.Runtime.Versioning;

namespace SecAudit.Infrastructure.Wmi;

[SupportedOSPlatform("windows")]
public sealed class WmiQuery : IWmiQuery
{
    public IEnumerable<IReadOnlyDictionary<string, object?>> Query(string scope, string wql)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentException.ThrowIfNullOrWhiteSpace(wql);

        var managementScope = new ManagementScope(scope);
        managementScope.Connect();
        using var searcher = new ManagementObjectSearcher(managementScope, new ObjectQuery(wql));
        using var collection = searcher.Get();

        var rows = new List<IReadOnlyDictionary<string, object?>>();
        foreach (var item in collection)
        {
            using var mo = (ManagementObject)item;
            var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in mo.Properties)
            {
                dict[prop.Name] = prop.Value;
            }
            rows.Add(dict);
        }
        return rows;
    }
}
