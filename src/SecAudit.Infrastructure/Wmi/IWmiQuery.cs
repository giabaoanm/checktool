namespace SecAudit.Infrastructure.Wmi;

public interface IWmiQuery
{
    /// <summary>
    /// Executes a WQL query against the given namespace and returns each row as a property map.
    /// </summary>
    IEnumerable<IReadOnlyDictionary<string, object?>> Query(string scope, string wql);
}
