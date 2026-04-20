using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.RemoteAccess.Detectors;

/// <summary>
/// Looks for the classic "WMI Event Subscription" persistence pattern (MITRE T1546.003):
///   __EventFilter   →   <consumer>EventConsumer   ←   __FilterToConsumerBinding
///
/// Default Windows installs ship 0 or a small whitelist of these in root\subscription.
/// Anything outside that whitelist is reported. We never delete — that's an IR action.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WmiPersistenceDetector
{
    public sealed record WmiPersistenceItem(string Class, string Name, string Detail);

    private static readonly HashSet<string> KnownBenignFilters = new(StringComparer.OrdinalIgnoreCase)
    {
        "BVTFilter",                         // Windows test/QA leftover
        "SCM Event Log Filter",
        "Microsoft-Windows-DSC"              // DSC consumes WMI events
    };

    private static readonly HashSet<string> KnownBenignConsumers = new(StringComparer.OrdinalIgnoreCase)
    {
        "BVTConsumer",
        "SCM Event Log Consumer"
    };

    private readonly IWmiQuery _wmi;
    private readonly ILogger<WmiPersistenceDetector> _logger;

    public WmiPersistenceDetector(IWmiQuery wmi, ILogger<WmiPersistenceDetector> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public IReadOnlyList<WmiPersistenceItem> Detect()
    {
        var hits = new List<WmiPersistenceItem>();

        // Filters
        SafeForEach(@"root\subscription", "SELECT Name, Query, EventNamespace FROM __EventFilter", row =>
        {
            var name = row.GetValueOrDefault("Name")?.ToString() ?? "(no name)";
            if (KnownBenignFilters.Contains(name))
            {
                return;
            }
            var query = row.GetValueOrDefault("Query")?.ToString() ?? "";
            var ns = row.GetValueOrDefault("EventNamespace")?.ToString() ?? "";
            hits.Add(new WmiPersistenceItem("__EventFilter", name,
                $"namespace={ns}; query={Truncate(query, 200)}"));
        });

        // Consumers — three flavours commonly abused
        foreach (var cls in new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer", "LogFileEventConsumer" })
        {
            SafeForEach(@"root\subscription",
                $"SELECT Name, CommandLineTemplate, ScriptText, ExecutablePath, ScriptingEngine, Filename FROM {cls}",
                row =>
                {
                    var name = row.GetValueOrDefault("Name")?.ToString() ?? "(no name)";
                    if (KnownBenignConsumers.Contains(name))
                    {
                        return;
                    }
                    var detail = cls switch
                    {
                        "CommandLineEventConsumer" =>
                            $"exe={row.GetValueOrDefault("ExecutablePath")}; cmd={Truncate(row.GetValueOrDefault("CommandLineTemplate")?.ToString(), 200)}",
                        "ActiveScriptEventConsumer" =>
                            $"engine={row.GetValueOrDefault("ScriptingEngine")}; script={Truncate(row.GetValueOrDefault("ScriptText")?.ToString(), 200)}",
                        "LogFileEventConsumer" =>
                            $"file={row.GetValueOrDefault("Filename")}",
                        _ => ""
                    };
                    hits.Add(new WmiPersistenceItem(cls, name, detail));
                });
        }

        // Bindings — what actually wires a filter to a consumer; if you have unknown
        // bindings *and* an unknown filter+consumer, you've found the trifecta.
        SafeForEach(@"root\subscription", "SELECT Filter, Consumer FROM __FilterToConsumerBinding", row =>
        {
            var f = row.GetValueOrDefault("Filter")?.ToString() ?? "";
            var c = row.GetValueOrDefault("Consumer")?.ToString() ?? "";
            // Skip whitelisted pairs.
            if (KnownBenignFilters.Any(k => f.Contains(k, StringComparison.OrdinalIgnoreCase)) &&
                KnownBenignConsumers.Any(k => c.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }
            hits.Add(new WmiPersistenceItem("__FilterToConsumerBinding", "(binding)",
                $"filter={Truncate(f, 120)}; consumer={Truncate(c, 120)}"));
        });

        return hits;
    }

    private void SafeForEach(string scope, string wql, Action<IReadOnlyDictionary<string, object?>> action)
    {
        try
        {
            foreach (var row in _wmi.Query(scope, wql))
            {
                action(row);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WMI query failed: {Scope} {Wql}", scope, wql);
        }
    }

    private static string Truncate(string? s, int max)
    {
        if (string.IsNullOrEmpty(s))
        {
            return "";
        }
        return s.Length <= max ? s : s[..max] + "…";
    }
}
