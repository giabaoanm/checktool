using System.Text.RegularExpressions;

namespace SecAudit.Modules.LogForensics.WebIncident;

public static partial class WebContentSignalDetector
{
    private static readonly string[] DefacementTerms =
    {
        "hacked by",
        "owned by",
        "pwned by",
        "defaced by",
        "website hacked",
        "hack team",
        "cyber army",
        "bị hack",
        "bi hack",
        "bị chiếm quyền",
        "bi chiem quyen",
        "đã bị tấn công",
        "da bi tan cong"
    };

    private static readonly string[] RansomTerms =
    {
        "your files are encrypted",
        "your data has been encrypted",
        "all your files",
        "decrypt your files",
        "ransom",
        "bitcoin",
        "monero",
        "pay to recover",
        "bị mã hóa",
        "bi ma hoa",
        "dữ liệu đã bị mã hóa",
        "du lieu da bi ma hoa"
    };

    private static readonly string[] CredentialOrPaymentTerms =
    {
        "verify your account",
        "confirm your password",
        "login to continue",
        "session expired",
        "credit card",
        "card number",
        "security code",
        "cvv",
        "bank account",
        "seed phrase",
        "private key"
    };

    private static readonly string[] SuspiciousScriptPatterns =
    {
        "eval(",
        "atob(",
        "String.fromCharCode",
        "fromCharCode(",
        "document.write(unescape",
        "unescape(",
        "setInterval(function",
        "setTimeout(function",
        "crypto-js",
        "coinhive",
        "cryptonight",
        "webminer",
        "skimmer",
        "magecart",
        "beef_hook",
        "beef.js"
    };

    public static WebContentSignals Analyze(string body, Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentNullException.ThrowIfNull(baseUri);

        var matched = new List<string>();
        foreach (var term in DefacementTerms.Concat(RansomTerms).Concat(CredentialOrPaymentTerms))
        {
            if (body.Contains(term, StringComparison.OrdinalIgnoreCase))
            {
                matched.Add(term);
            }
        }

        var externalHosts = ExtractExternalHosts(body, baseUri);
        var suspiciousPatterns = DetectSuspiciousPatterns(body);
        return new WebContentSignals(
            Title: ExtractTitle(body),
            DefacementMarker: DefacementTerms.Any(t => body.Contains(t, StringComparison.OrdinalIgnoreCase)),
            RansomOrEncryptionMarker: RansomTerms.Any(t => body.Contains(t, StringComparison.OrdinalIgnoreCase)),
            CredentialOrPaymentPhishingMarker: CredentialOrPaymentTerms.Count(t => body.Contains(t, StringComparison.OrdinalIgnoreCase)) >= 2,
            ExternalRedirectOrFrame: externalHosts.Count > 0,
            SuspiciousScriptOrObfuscation: suspiciousPatterns.Count > 0 || LongBase64Regex().IsMatch(body),
            HiddenIframeOrSkimmerMarker: HiddenIframeRegex().IsMatch(body)
                || BodyContainsAny(body, "cardNumber", "cc_number", "payment-form", "checkout iframe"),
            MatchedTerms: matched,
            ExternalHosts: externalHosts,
            SuspiciousPatterns: suspiciousPatterns,
            LinkedResources: ExtractLinkedResources(body, baseUri));
    }

    public static string? ExtractTitle(string body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var match = TitleRegex().Match(body);
        return match.Success
            ? Regex.Replace(match.Groups[1].Value, @"\s+", " ").Trim()
            : null;
    }

    public static IReadOnlyList<string> ExtractExternalHosts(string body, Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentNullException.ThrowIfNull(baseUri);

        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in ExternalUrlRegex().Matches(body))
        {
            var value = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                continue;
            }
            if (!string.Equals(uri.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase))
            {
                hosts.Add(uri.Host);
            }
        }

        foreach (Match match in MetaRefreshRegex().Matches(body))
        {
            var value = match.Groups[1].Value;
            var idx = value.IndexOf("url=", StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                continue;
            }
            var candidate = value[(idx + 4)..].Trim(' ', '\'', '"');
            if (Uri.TryCreate(baseUri, candidate, out var uri)
                && !string.Equals(uri.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase))
            {
                hosts.Add(uri.Host);
            }
        }

        return hosts.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static IReadOnlyList<WebLinkedResource> ExtractLinkedResources(string body, Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentNullException.ThrowIfNull(baseUri);

        var resources = new Dictionary<string, WebLinkedResource>(StringComparer.OrdinalIgnoreCase);
        AddResources(resources, ScriptSrcRegex().Matches(body), "script", baseUri);
        AddResources(resources, IframeSrcRegex().Matches(body), "iframe", baseUri);
        AddResources(resources, LinkHrefRegex().Matches(body), "link", baseUri);
        AddResources(resources, FormActionRegex().Matches(body), "form", baseUri);
        return resources.Values
            .OrderByDescending(r => r.IsExternal)
            .ThenBy(r => r.Kind, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Url, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> DetectSuspiciousPatterns(string body)
    {
        ArgumentNullException.ThrowIfNull(body);

        var patterns = new List<string>();
        foreach (var pattern in SuspiciousScriptPatterns)
        {
            if (body.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                patterns.Add(pattern);
            }
        }

        if (LongBase64Regex().IsMatch(body))
        {
            patterns.Add("long-base64-or-packed-text");
        }
        if (HiddenIframeRegex().IsMatch(body))
        {
            patterns.Add("hidden-iframe");
        }

        return patterns.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddResources(
        IDictionary<string, WebLinkedResource> resources,
        MatchCollection matches,
        string kind,
        Uri baseUri)
    {
        foreach (Match match in matches)
        {
            var raw = match.Groups[1].Value.Trim();
            if (string.IsNullOrWhiteSpace(raw)
                || raw.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
                || raw.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)
                || raw.StartsWith('#'))
            {
                continue;
            }
            if (!Uri.TryCreate(baseUri, raw, out var uri)
                || uri.Scheme is not ("http" or "https"))
            {
                continue;
            }

            var url = uri.ToString();
            resources[url] = new WebLinkedResource(
                url,
                kind,
                !string.Equals(uri.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase));
        }
    }

    private static bool BodyContainsAny(string body, params string[] terms)
        => terms.Any(term => body.Contains(term, StringComparison.OrdinalIgnoreCase));

    [GeneratedRegex("<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex TitleRegex();

    [GeneratedRegex(
        "(?:src|href)\\s*=\\s*[\"'](https?://[^\"'#>\\s]+)|(?:window\\.location|location\\.href)\\s*=\\s*[\"'](https?://[^\"']+)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex ExternalUrlRegex();

    [GeneratedRegex(
        "<meta[^>]+http-equiv\\s*=\\s*[\"']?refresh[\"']?[^>]+content\\s*=\\s*[\"']([^\"']+)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex MetaRefreshRegex();

    [GeneratedRegex("<script[^>]+src\\s*=\\s*[\"']([^\"']+)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex ScriptSrcRegex();

    [GeneratedRegex("<iframe[^>]+src\\s*=\\s*[\"']([^\"']+)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex IframeSrcRegex();

    [GeneratedRegex("<link[^>]+href\\s*=\\s*[\"']([^\"']+)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex LinkHrefRegex();

    [GeneratedRegex("<form[^>]+action\\s*=\\s*[\"']([^\"']+)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex FormActionRegex();

    [GeneratedRegex("<iframe[^>]+(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|width\\s*=\\s*[\"']?0|height\\s*=\\s*[\"']?0)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HiddenIframeRegex();

    [GeneratedRegex("[A-Za-z0-9+/]{240,}={0,2}", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex LongBase64Regex();
}
