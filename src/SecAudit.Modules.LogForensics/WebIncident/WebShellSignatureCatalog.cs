using System.Text.RegularExpressions;

namespace SecAudit.Modules.LogForensics.WebIncident;

/// <summary>
/// Pattern catalog for the most common public webshells observed on compromised
/// PHP/ASP/JSP webroots. Detection is regex-based and runs only on files inside the
/// imported webroot evidence — never on live traffic. Each signature is intentionally
/// conservative (≥2 distinct markers required for high-confidence) to avoid flagging
/// CMS templates that legitimately use eval/preg_replace/base64_decode.
///
/// <para>Sources: Mandiant M-Trends webshell catalog, MITRE ATT&amp;CK T1505.003,
/// TrustedSec / SANS public webshell roundups. Patterns kept short and obvious so
/// they survive minor attacker edits without false-negative drift.</para>
/// </summary>
public static partial class WebShellSignatureCatalog
{
    public sealed record WebShellSignature(
        string Family,
        string Description,
        IReadOnlyList<Regex> Patterns,
        int MinMatches);

    public sealed record WebShellHit(
        string Family,
        string Description,
        IReadOnlyList<string> MatchedPatternNames);

    private static readonly Regex[] ChinaChopperPatterns =
    {
        // Classic one-liner: <?php @eval($_POST['x']);?> with single-letter param.
        new(@"@eval\s*\(\s*\$_(POST|REQUEST|GET)\s*\[\s*['""][a-zA-Z]\s*['""]\s*\]\s*\)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        // ASPX variant: <%@ Page Language="Jscript"%><%eval(Request.Item["x"]
        new(@"eval\s*\(\s*Request\.Item\s*\[",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
    };

    private static readonly Regex[] B374kPatterns =
    {
        new(@"\bb374k\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"function\s+b374k_", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"\$GLOBALS\['__b374k", RegexOptions.Compiled, TimeSpan.FromSeconds(2)),
    };

    private static readonly Regex[] WeevelyPatterns =
    {
        new(@"function\s+wfe_", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"\$h\s*=\s*function\s*\(\s*\$k\s*,\s*\$s\s*\)", RegexOptions.Compiled, TimeSpan.FromSeconds(2)),
        new(@"openssl_decrypt\s*\(\s*\$_COOKIE", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
    };

    private static readonly Regex[] C99R57Patterns =
    {
        new(@"\bc99shell\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"\br57shell\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"safe_mode\s+bypass", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"@set_magic_quotes_runtime", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
    };

    private static readonly Regex[] AspxSpyPatterns =
    {
        new(@"\baspxspy\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"Server\.Execute\s*\(\s*Request\.QueryString", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        new(@"Process\s*\.\s*Start\s*\(\s*['""]cmd\.exe['""]", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
    };

    private static readonly Regex[] GenericObfuscationPatterns =
    {
        // Layered obfuscation common to many webshells: eval/assert + decoding chain.
        new(@"(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
        // Variable-variable execution: $$a($$b) — used to hide command names.
        new(@"\$\$\w+\s*\(\s*\$\$\w+", RegexOptions.Compiled, TimeSpan.FromSeconds(2)),
        // create_function — deprecated but still favoured by old shells for runtime code.
        new(@"create_function\s*\(\s*['""]['""]?", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)),
    };

    public static IReadOnlyList<WebShellSignature> Signatures { get; } = new[]
    {
        new WebShellSignature(
            Family: "China-Chopper",
            Description: "Single-line eval($_POST/$_REQUEST) one-liner; widely deployed by APT groups.",
            Patterns: ChinaChopperPatterns,
            MinMatches: 1),
        new WebShellSignature(
            Family: "b374k",
            Description: "PHP web manager shell with file/DB browser GUI.",
            Patterns: B374kPatterns,
            MinMatches: 1),
        new WebShellSignature(
            Family: "Weevely",
            Description: "PHP shell using cookie-encrypted command transport.",
            Patterns: WeevelyPatterns,
            MinMatches: 2),
        new WebShellSignature(
            Family: "c99/r57",
            Description: "Classic PHP web admin shells, often dropped by mass scanners.",
            Patterns: C99R57Patterns,
            MinMatches: 1),
        new WebShellSignature(
            Family: "ASPXSpy",
            Description: "ASP.NET shell with file/process/registry browser.",
            Patterns: AspxSpyPatterns,
            MinMatches: 1),
        new WebShellSignature(
            Family: "GenericObfuscatedShell",
            Description: "Layered eval+decoder chain — typical of repackaged/custom webshells.",
            Patterns: GenericObfuscationPatterns,
            MinMatches: 1),
    };

    /// <summary>
    /// Scans <paramref name="content"/> against every signature and returns the families that
    /// matched at or above <see cref="WebShellSignature.MinMatches"/>. Returns an empty list
    /// for inputs &gt;5 MB to avoid catastrophic-backtracking risk on attacker-shaped content.
    /// </summary>
    public static IReadOnlyList<WebShellHit> Scan(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (content.Length == 0 || content.Length > 5 * 1024 * 1024)
        {
            return Array.Empty<WebShellHit>();
        }

        var hits = new List<WebShellHit>();
        foreach (var sig in Signatures)
        {
            var matched = new List<string>();
            for (var i = 0; i < sig.Patterns.Count; i++)
            {
                try
                {
                    if (sig.Patterns[i].IsMatch(content))
                    {
                        matched.Add($"{sig.Family}#{i}");
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    // Skip — file is hostile to regex; downstream baseline diff still flags it.
                }
            }
            if (matched.Count >= sig.MinMatches)
            {
                hits.Add(new WebShellHit(sig.Family, sig.Description, matched));
            }
        }
        return hits;
    }
}
