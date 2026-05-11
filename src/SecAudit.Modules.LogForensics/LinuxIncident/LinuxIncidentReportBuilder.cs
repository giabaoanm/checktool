using System.Globalization;
using System.Text;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Renders an IR-analyst-style report from a <see cref="LinuxIncidentAnalyzer.AnalysisResult"/>.
/// The output mirrors the structure that a forensic analyst would write up by hand:
/// timeline → root cause → payload/crypto → persistence → IOC table → recommendations.
///
/// <para>Two formats:</para>
/// <list type="bullet">
///   <item><see cref="BuildMarkdown"/> — primary, easy to paste into ticket / chat / wiki.</item>
///   <item><see cref="BuildHtml"/> — minimal self-contained HTML so SOC managers can
///         double-click and read in browser without extra tooling.</item>
/// </list>
///
/// <para>Categorisation is driven by Finding ID prefixes from
/// <see cref="LinuxIncidentAnalyzer"/> (LIN-SSH-*, LIN-SUDOERS-*, LIN-CRON-*,
/// LIN-RANSOM-*, LIN-ENCRYPTED-*, LIN-IOC-*) — adding a new analyzer family
/// only needs a new switch arm here.</para>
/// </summary>
public static class LinuxIncidentReportBuilder
{
    public sealed record ReportContext(
        string Asset,
        string SourcePath,
        DateTimeOffset GeneratedAt,
        LinuxIncidentAnalyzer.AnalysisResult Result);

    public static string BuildMarkdown(ReportContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        var sb = new StringBuilder(8 * 1024);
        var inv = CultureInfo.InvariantCulture;

        var (sshFindings, sudoFindings, cronFindings, ransomFindings, encExtFindings, summaryFindings, otherFindings)
            = Categorise(ctx.Result.Findings);
        var (ips, urls, emails, btc, others) = CategoriseIocs(ctx.Result.ExtractedIocs);

        sb.AppendLine($"# Báo cáo điều tra sự cố — `{ctx.Asset}`");
        sb.AppendLine();
        sb.AppendLine($"- **Asset:** `{ctx.Asset}`");
        sb.AppendLine($"- **Nguồn bằng chứng:** `{ctx.SourcePath}`");
        sb.AppendLine($"- **Thời điểm tạo báo cáo:** {ctx.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", inv)}");
        sb.AppendLine($"- **Tổng số tệp đã quét:** {ctx.Result.FilesScanned:N0}");
        sb.AppendLine($"- **Tổng số finding:** {ctx.Result.Findings.Count}  ");
        sb.AppendLine($"  - Critical: {Count(ctx.Result.Findings, Severity.Critical)}");
        sb.AppendLine($"  - High: {Count(ctx.Result.Findings, Severity.High)}");
        sb.AppendLine($"  - Medium: {Count(ctx.Result.Findings, Severity.Medium)}");
        sb.AppendLine($"- **Tổng số IOC trích xuất:** {ctx.Result.ExtractedIocs.Count}");
        sb.AppendLine();

        // --- 1. Timeline ---
        sb.AppendLine("## 1. Dòng thời gian & dấu vết truy cập");
        if (sshFindings.Count == 0)
        {
            sb.AppendLine("*Không phát hiện sự kiện SSH bất thường trong auth.log.*");
        }
        else
        {
            sb.AppendLine();
            sb.AppendLine("| Mức | ID | Mô tả |");
            sb.AppendLine("|---|---|---|");
            foreach (var f in sshFindings)
            {
                sb.AppendLine($"| **{f.Severity}** | `{f.Id}` | {Escape(f.Title)} |");
            }
            sb.AppendLine();
            foreach (var f in sshFindings)
            {
                sb.AppendLine($"### {f.Title}");
                sb.AppendLine();
                AppendEvidence(sb, f);
                AppendAttackTechniques(sb, f);
                sb.AppendLine();
            }
        }
        sb.AppendLine();

        // --- 2. Cách kẻ tấn công có quyền root ---
        sb.AppendLine("## 2. Đánh giá leo thang đặc quyền (sudoers)");
        if (sudoFindings.Count == 0)
        {
            sb.AppendLine("*Không phát hiện cấu hình sudoers nguy hiểm.*");
        }
        else
        {
            foreach (var f in sudoFindings)
            {
                sb.AppendLine($"- **{f.Title}**");
                AppendEvidenceInline(sb, f);
                sb.AppendLine();
            }
        }
        sb.AppendLine();

        // --- 3. Payload & cấu hình mã hoá ---
        sb.AppendLine("## 3. Payload & cấu hình mã hoá");
        if (ransomFindings.Count == 0 && encExtFindings.Count == 0)
        {
            sb.AppendLine("*Không phát hiện ransom note hay chuỗi file mã hoá.*");
        }
        else
        {
            foreach (var f in ransomFindings)
            {
                sb.AppendLine($"### {f.Title}");
                sb.AppendLine();
                AppendEvidence(sb, f);
                AppendAttackTechniques(sb, f);
                sb.AppendLine();
            }
            foreach (var f in encExtFindings)
            {
                sb.AppendLine($"### {f.Title}");
                sb.AppendLine();
                AppendEvidence(sb, f);
                AppendAttackTechniques(sb, f);
                sb.AppendLine();
            }
        }
        sb.AppendLine();

        // --- 4. Persistence ---
        sb.AppendLine("## 4. Persistence (cron / scheduled)");
        if (cronFindings.Count == 0)
        {
            sb.AppendLine("*Không phát hiện cron persistence đáng ngờ.*");
        }
        else
        {
            foreach (var f in cronFindings)
            {
                sb.AppendLine($"- **{f.Title}**");
                AppendEvidenceInline(sb, f);
                sb.AppendLine();
            }
        }
        sb.AppendLine();

        // --- 5. IOC summary table ---
        sb.AppendLine("## 5. IOC tóm tắt");
        sb.AppendLine();
        sb.AppendLine("| Loại | Giá trị |");
        sb.AppendLine("|---|---|");
        foreach (var ip in ips) { sb.AppendLine($"| IP nguồn / C2 | `{Escape(ip)}` |"); }
        foreach (var url in urls) { sb.AppendLine($"| URL payload / C2 | `{Escape(url)}` |"); }
        foreach (var em in emails) { sb.AppendLine($"| Email tống tiền | `{Escape(em)}` |"); }
        foreach (var b in btc) { sb.AppendLine($"| Ví BTC | `{Escape(b)}` |"); }
        foreach (var o in others) { sb.AppendLine($"| Khác | `{Escape(o)}` |"); }
        if (ips.Count + urls.Count + emails.Count + btc.Count + others.Count == 0)
        {
            sb.AppendLine("| — | *Không trích xuất được IOC* |");
        }
        sb.AppendLine();

        // --- 6. Khuyến nghị ---
        sb.AppendLine("## 6. Khuyến nghị xử lý");
        sb.AppendLine();
        var allRem = ctx.Result.Findings
            .Where(f => f.Severity >= Severity.Medium)
            .Select(f => f.Remediation)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (allRem.Count == 0)
        {
            sb.AppendLine("- Không có khuyến nghị mức Medium+ trong phiên này.");
        }
        else
        {
            var i = 1;
            foreach (var rem in allRem)
            {
                sb.AppendLine($"{i++}. {rem}");
                sb.AppendLine();
            }
        }

        // --- Other findings (nếu có) ---
        if (otherFindings.Count > 0 || summaryFindings.Count > 0)
        {
            sb.AppendLine("## 7. Findings khác / tóm tắt module");
            foreach (var f in summaryFindings.Concat(otherFindings))
            {
                sb.AppendLine($"- **[{f.Severity}] {f.Title}** (`{f.Id}`)");
            }
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine($"*Báo cáo do **SecAudit** sinh tự động lúc {ctx.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", inv)}.*");
        return sb.ToString();
    }

    public static string BuildHtml(ReportContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        var md = BuildMarkdown(ctx);
        var html = ConvertMarkdownToHtml(md);
        var sb = new StringBuilder(html.Length + 2048);
        sb.AppendLine("<!doctype html>");
        sb.AppendLine("<html lang=\"vi\"><head><meta charset=\"utf-8\">");
        sb.Append("<title>SecAudit — Báo cáo Linux IR — ").Append(Escape(ctx.Asset)).AppendLine("</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("  body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 1100px; margin: 24px auto; padding: 0 24px; color: #1c1c1c; line-height: 1.55; }");
        sb.AppendLine("  h1 { color: #b22; border-bottom: 2px solid #b22; padding-bottom: 6px; }");
        sb.AppendLine("  h2 { color: #224; border-bottom: 1px solid #ccd; padding-bottom: 4px; margin-top: 28px; }");
        sb.AppendLine("  h3 { color: #333; margin-top: 18px; }");
        sb.AppendLine("  table { border-collapse: collapse; margin: 8px 0; width: 100%; }");
        sb.AppendLine("  th, td { border: 1px solid #ccd; padding: 6px 10px; text-align: left; vertical-align: top; }");
        sb.AppendLine("  th { background: #eef; }");
        sb.AppendLine("  code { background: #f4f4f8; padding: 1px 4px; border-radius: 3px; font-family: Consolas, monospace; font-size: 0.92em; word-break: break-all; }");
        sb.AppendLine("  pre { background: #f4f4f8; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: Consolas, monospace; font-size: 0.9em; white-space: pre-wrap; }");
        sb.AppendLine("  strong { color: #b22; }");
        sb.AppendLine("  hr { border: none; border-top: 1px solid #ccd; margin: 24px 0; }");
        sb.AppendLine("  .meta { color: #666; font-style: italic; }");
        sb.AppendLine("</style></head><body>");
        sb.Append(html);
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    // ---------------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------------

    private static (
        List<Finding> ssh, List<Finding> sudo, List<Finding> cron,
        List<Finding> ransom, List<Finding> encExt,
        List<Finding> summary, List<Finding> other)
        Categorise(IEnumerable<Finding> findings)
    {
        var ssh = new List<Finding>();
        var sudo = new List<Finding>();
        var cron = new List<Finding>();
        var ransom = new List<Finding>();
        var encExt = new List<Finding>();
        var summary = new List<Finding>();
        var other = new List<Finding>();
        foreach (var f in findings.OrderByDescending(f => f.Severity))
        {
            if (f.Id.StartsWith("LIN-SSH-", StringComparison.Ordinal)) { ssh.Add(f); }
            else if (f.Id.StartsWith("LIN-SUDOERS-", StringComparison.Ordinal)) { sudo.Add(f); }
            else if (f.Id.StartsWith("LIN-CRON-", StringComparison.Ordinal)) { cron.Add(f); }
            else if (f.Id.StartsWith("LIN-RANSOM-", StringComparison.Ordinal)) { ransom.Add(f); }
            else if (f.Id.StartsWith("LIN-ENCRYPTED-", StringComparison.Ordinal)) { encExt.Add(f); }
            else if (f.Id.StartsWith("LIN-IOC-", StringComparison.Ordinal)) { summary.Add(f); }
            else { other.Add(f); }
        }
        return (ssh, sudo, cron, ransom, encExt, summary, other);
    }

    private static (List<string> ips, List<string> urls, List<string> emails, List<string> btc, List<string> others)
        CategoriseIocs(IEnumerable<string> iocs)
    {
        var ips = new List<string>();
        var urls = new List<string>();
        var emails = new List<string>();
        var btc = new List<string>();
        var others = new List<string>();
        foreach (var i in iocs.OrderBy(x => x, StringComparer.Ordinal))
        {
            if (i.StartsWith("ip:", StringComparison.Ordinal)) { ips.Add(i["ip:".Length..]); }
            else if (i.StartsWith("url:", StringComparison.Ordinal)) { urls.Add(i["url:".Length..]); }
            else if (i.StartsWith("email:", StringComparison.Ordinal)) { emails.Add(i["email:".Length..]); }
            else if (i.StartsWith("btc:", StringComparison.Ordinal)) { btc.Add(i["btc:".Length..]); }
            else { others.Add(i); }
        }
        return (ips, urls, emails, btc, others);
    }

    private static int Count(IEnumerable<Finding> findings, Severity sev)
        => findings.Count(f => f.Severity == sev);

    private static void AppendEvidence(StringBuilder sb, Finding f)
    {
        sb.AppendLine("**Bằng chứng:**");
        sb.AppendLine();
        sb.AppendLine("```");
        sb.AppendLine(f.Evidence);
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("**Khuyến nghị:** " + f.Remediation);
    }

    private static void AppendEvidenceInline(StringBuilder sb, Finding f)
    {
        sb.AppendLine($"  - Bằng chứng: `{Escape(f.Evidence.Replace('\n', ' ').Replace('\r', ' '))}`");
        sb.AppendLine($"  - Khuyến nghị: {f.Remediation}");
    }

    private static void AppendAttackTechniques(StringBuilder sb, Finding f)
    {
        if (f.AttackTechniqueIds.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("**MITRE ATT&CK:** " + string.Join(", ", f.AttackTechniqueIds.Select(t => $"`{t}`")));
        }
    }

    private static string Escape(string s)
        => s.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("|", "\\|", StringComparison.Ordinal);

    /// <summary>
    /// Minimal Markdown→HTML converter: handles headings, bold, inline code, fenced
    /// code blocks, bullet lists, and pipe-tables — exactly what BuildMarkdown emits.
    /// Not a general MD parser: it intentionally sticks to the tag set we generate.
    /// </summary>
    private static string ConvertMarkdownToHtml(string md)
    {
        var sb = new StringBuilder(md.Length * 2);
        var lines = md.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var inCode = false;
        var inTable = false;
        var inList = false;

        bool IsTableRow(string l) => l.StartsWith('|') && l.EndsWith('|');

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];

            if (line.StartsWith("```", StringComparison.Ordinal))
            {
                if (!inCode) { CloseList(sb, ref inList); CloseTable(sb, ref inTable); sb.AppendLine("<pre>"); inCode = true; }
                else { sb.AppendLine("</pre>"); inCode = false; }
                continue;
            }
            if (inCode) { sb.AppendLine(EscapeHtmlOnly(line)); continue; }

            if (string.IsNullOrWhiteSpace(line))
            {
                CloseList(sb, ref inList);
                CloseTable(sb, ref inTable);
                sb.AppendLine();
                continue;
            }

            if (IsTableRow(line))
            {
                CloseList(sb, ref inList);
                if (!inTable) { sb.AppendLine("<table>"); inTable = true; }
                // Skip the |---|---| separator row.
                if (line.Replace("|", "", StringComparison.Ordinal).Trim().All(c => c is '-' or ':' or ' '))
                {
                    continue;
                }
                var cells = line.Trim().Trim('|').Split('|');
                var isHeader = (i + 1 < lines.Length)
                    && lines[i + 1].Replace("|", "", StringComparison.Ordinal).Trim().All(c => c is '-' or ':' or ' ');
                sb.Append("  <tr>");
                foreach (var c in cells)
                {
                    var t = isHeader ? "th" : "td";
                    sb.Append('<').Append(t).Append('>').Append(InlineFormat(c.Trim())).Append("</").Append(t).Append('>');
                }
                sb.AppendLine("</tr>");
                continue;
            }
            CloseTable(sb, ref inTable);

            if (line.StartsWith("# ", StringComparison.Ordinal))
            { CloseList(sb, ref inList); sb.Append("<h1>").Append(InlineFormat(line[2..])).AppendLine("</h1>"); continue; }
            if (line.StartsWith("## ", StringComparison.Ordinal))
            { CloseList(sb, ref inList); sb.Append("<h2>").Append(InlineFormat(line[3..])).AppendLine("</h2>"); continue; }
            if (line.StartsWith("### ", StringComparison.Ordinal))
            { CloseList(sb, ref inList); sb.Append("<h3>").Append(InlineFormat(line[4..])).AppendLine("</h3>"); continue; }
            if (line.StartsWith("---", StringComparison.Ordinal))
            { CloseList(sb, ref inList); sb.AppendLine("<hr>"); continue; }

            if (line.StartsWith("- ", StringComparison.Ordinal) || line.StartsWith("  - ", StringComparison.Ordinal))
            {
                if (!inList) { sb.AppendLine("<ul>"); inList = true; }
                var content = line.TrimStart().Substring(2);
                sb.Append("  <li>").Append(InlineFormat(content)).AppendLine("</li>");
                continue;
            }
            if (line.Length > 2 && char.IsDigit(line[0]) && line[1] == '.')
            {
                if (!inList) { sb.AppendLine("<ol>"); inList = true; }
                var idx = line.IndexOf(' ', StringComparison.Ordinal);
                if (idx > 0)
                {
                    sb.Append("  <li>").Append(InlineFormat(line[(idx + 1)..])).AppendLine("</li>");
                    continue;
                }
            }

            CloseList(sb, ref inList);
            sb.Append("<p>").Append(InlineFormat(line)).AppendLine("</p>");
        }
        CloseList(sb, ref inList);
        CloseTable(sb, ref inTable);
        if (inCode) { sb.AppendLine("</pre>"); }
        return sb.ToString();
    }

    private static void CloseList(StringBuilder sb, ref bool inList)
    {
        if (inList) { sb.AppendLine("</ul>"); inList = false; }
    }

    private static void CloseTable(StringBuilder sb, ref bool inTable)
    {
        if (inTable) { sb.AppendLine("</table>"); inTable = false; }
    }

    private static string EscapeHtmlOnly(string s)
        => s.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);

    private static string InlineFormat(string s)
    {
        var html = EscapeHtmlOnly(s);
        // bold: **text**
        html = System.Text.RegularExpressions.Regex.Replace(
            html, @"\*\*(.+?)\*\*", "<strong>$1</strong>",
            System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
        // inline code: `text`
        html = System.Text.RegularExpressions.Regex.Replace(
            html, @"`([^`]+)`", "<code>$1</code>",
            System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
        // markdown table cell escape: \| → |
        html = html.Replace("\\|", "|", StringComparison.Ordinal);
        return html;
    }
}
