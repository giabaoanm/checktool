using System.Reflection;
using System.Text.Json;
using SecAudit.Cve.Pipeline.Models;

namespace SecAudit.Cve.Pipeline;

/// <summary>
/// Loads the embedded fast-path rules. These are evaluated independently of the NVD SQLite
/// database so the app ships with a minimum of critical coverage even on a first-run machine
/// that has never synced an NVD dataset.
/// </summary>
public static class FastPathRuleLoader
{
    private const string ResourceName = "SecAudit.Cve.Pipeline.Seed.fast-path-cves.json";

    public static IReadOnlyList<FastPathRule> Load()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("Embedded resource missing: " + ResourceName);

        using var doc = JsonDocument.Parse(stream);
        var rules = new List<FastPathRule>();
        foreach (var node in doc.RootElement.GetProperty("rules").EnumerateArray())
        {
            var kbs = node.GetProperty("required_kb_any").EnumerateArray()
                .Select(x => x.GetString() ?? string.Empty)
                .Where(x => x.Length > 0)
                .ToArray();

            rules.Add(new FastPathRule(
                Id: node.GetProperty("id").GetString() ?? "",
                Title: node.GetProperty("title").GetString() ?? "",
                Cvss: node.TryGetProperty("cvss", out var c) ? c.GetDouble() : 0,
                Severity: node.GetProperty("severity").GetString() ?? "High",
                RequiredKbAny: kbs,
                AppliesToOsBuildsBelow: node.TryGetProperty("applies_to_os_builds_below", out var b) && b.ValueKind == JsonValueKind.Number
                    ? b.GetInt32() : null,
                AppliesToOsBuildsAbove: node.TryGetProperty("applies_to_os_builds_above", out var a) && a.ValueKind == JsonValueKind.Number
                    ? a.GetInt32() : null,
                Reference: node.TryGetProperty("reference", out var r) ? r.GetString() ?? "" : "",
                SupersededBySecurityUpdateOnOrAfter: node.TryGetProperty(
                    "superseded_by_security_update_on_or_after", out var s)
                    ? s.GetString()
                    : null));
        }
        return rules;
    }
}
