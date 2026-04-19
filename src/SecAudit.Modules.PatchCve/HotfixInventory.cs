using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Wmi;

namespace SecAudit.Modules.PatchCve;

/// <summary>
/// Enumerates installed Windows hotfixes via Win32_QuickFixEngineering. This is what
/// <c>Get-HotFix</c> wraps; it only sees "classic" updates, not servicing stack / Windows
/// Update delivery optimisation increments, but it's enough for the fast-path KB matching
/// we do in Iteration 3.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HotfixInventory
{
    private readonly IWmiQuery _wmi;
    private readonly ILogger<HotfixInventory> _logger;

    public HotfixInventory(IWmiQuery wmi, ILogger<HotfixInventory> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public IReadOnlySet<string> CollectInstalledKbs()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var rows = _wmi.Query(@"\\.\ROOT\CIMV2",
                "SELECT HotFixID FROM Win32_QuickFixEngineering");
            foreach (var row in rows)
            {
                if (row.TryGetValue("HotFixID", out var v) && v?.ToString() is { Length: > 0 } kb)
                {
                    set.Add(kb.Trim());
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Win32_QuickFixEngineering query failed");
        }
        return set;
    }
}
