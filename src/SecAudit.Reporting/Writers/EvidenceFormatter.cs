using System.Text;

namespace SecAudit.Reporting.Writers;

/// <summary>
/// Shared evidence post-processor used by every report writer (HTML, PDF, DOCX) so they
/// render finding evidence the same way. Two responsibilities:
///
/// <list type="number">
///   <item>Replace bullet markers (<c>'• '</c> at the start of a line) with sequential
///         numbering (<c>'1. '</c>, <c>'2. '</c>, …). Numbered lists scan faster than
///         bullets when the SOC operator wants to refer to "item 3" in a meeting.</item>
///   <item>Preserve indentation of continuation lines under each bulleted item — the
///         module emits two spaces of indent for sub-lines, which the writers' wrapping
///         needs to keep so multi-line evidence stays readable.</item>
/// </list>
///
/// Modules that emit a single-paragraph evidence string with no <c>'• '</c> bullets are
/// passed through unchanged. The transform is intentionally idempotent — running it twice
/// produces the same output as running it once.
/// </summary>
public static class EvidenceFormatter
{
    /// <summary>
    /// Rewrite <paramref name="raw"/> evidence so each line beginning with <c>"• "</c>
    /// becomes <c>"1. "</c>, <c>"2. "</c>, … in encounter order. Indented continuation
    /// lines (those starting with whitespace and not a bullet) are kept as-is.
    /// </summary>
    public static string NumberBullets(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) { return string.Empty; }
        if (!raw.Contains("• ", StringComparison.Ordinal))
        {
            return raw;
        }

        var sb = new StringBuilder(raw.Length + 16);
        int n = 0;
        var lines = raw.Replace("\r\n", "\n").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            // Strict prefix "• " (Unicode U+2022 + space) only — anything else is a
            // continuation line and gets preserved verbatim.
            if (line.StartsWith("• ", StringComparison.Ordinal))
            {
                n++;
                sb.Append(n).Append(". ").Append(line.AsSpan(2));
            }
            else
            {
                sb.Append(line);
            }
            if (i < lines.Length - 1) { sb.Append('\n'); }
        }
        return sb.ToString();
    }
}
