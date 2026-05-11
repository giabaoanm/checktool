using System.Globalization;
using System.Text;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.WindowsIr;

/// <summary>
/// Combines findings from all five Windows IR modules
/// (Browser / Office / AD-Attack / Ransomware-Precursor / Recent-Files) into a
/// single SOC-grade narrative. Mirrors the 6-section layout used by
/// <c>LinuxIncidentReportBuilder</c> so analysts see the same shape regardless
/// of OS being investigated.
///
/// <para>Categorisation is driven by the Finding ID prefix that each module
/// emits — adding a future module just means adding one switch arm.</para>
/// </summary>
public static class WindowsIrReportBuilder
{
    public sealed record ReportContext(
        string Asset,
        string SourcePath,
        DateTimeOffset GeneratedAt,
        IReadOnlyList<Finding> AllFindings,
        IReadOnlyList<string> ExtractedIocs,
        int FilesScanned);

    public static string BuildMarkdown(ReportContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        var sb = new StringBuilder(16 * 1024);
        var inv = CultureInfo.InvariantCulture;

        var (browser, office, ad, ransom, recent, other) = Categorise(ctx.AllFindings);
        var (ips, urls, emails, btc, files, others) = CategoriseIocs(ctx.ExtractedIocs);

        sb.AppendLine($"# Báo cáo điều tra Windows IR — `{ctx.Asset}`");
        sb.AppendLine();
        sb.AppendLine($"- **Asset:** `{ctx.Asset}`");
        sb.AppendLine($"- **Nguồn quét:** `{ctx.SourcePath}`");
        sb.AppendLine($"- **Thời điểm tạo báo cáo:** {ctx.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", inv)}");
        sb.AppendLine($"- **Tổng số tệp/profile đã quét:** {ctx.FilesScanned:N0}");
        sb.AppendLine($"- **Tổng số finding:** {ctx.AllFindings.Count}  ");
        sb.AppendLine($"  - Critical: {Count(ctx.AllFindings, Severity.Critical)}");
        sb.AppendLine($"  - High: {Count(ctx.AllFindings, Severity.High)}");
        sb.AppendLine($"  - Medium: {Count(ctx.AllFindings, Severity.Medium)}");
        sb.AppendLine($"- **Tổng số IOC trích xuất:** {ctx.ExtractedIocs.Count}");
        sb.AppendLine();

        // --- 1. Initial Access — phishing / drive-by / Office ---
        sb.AppendLine("## 1. Initial Access — phishing / drive-by / Office attachment");
        if (browser.Count == 0 && office.Count == 0)
        {
            sb.AppendLine("*Không phát hiện dấu vết phishing email hay drive-by web.*");
        }
        else
        {
            if (office.Count > 0)
            {
                sb.AppendLine("### 1a. Office & Outlook attachment");
                foreach (var f in office) { AppendFinding(sb, f); }
            }
            if (browser.Count > 0)
            {
                sb.AppendLine("### 1b. Browser history & downloads");
                foreach (var f in browser) { AppendFinding(sb, f); }
            }
        }
        sb.AppendLine();

        // --- 2. User Execution — recent files ---
        sb.AppendLine("## 2. User Execution — file đã mở gần đây / USB / LNK dropper");
        if (recent.Count == 0)
        {
            sb.AppendLine("*Không phát hiện artifact thực thi gần đây đáng ngờ.*");
        }
        else
        {
            foreach (var f in recent) { AppendFinding(sb, f); }
        }
        sb.AppendLine();

        // --- 3. Credential Access — AD attack ---
        sb.AppendLine("## 3. Credential Access — AD attack patterns");
        if (ad.Count == 0)
        {
            sb.AppendLine("*Không phát hiện Kerberoasting / AS-REP / DCSync / Zerologon.*");
        }
        else
        {
            foreach (var f in ad) { AppendFinding(sb, f); }
        }
        sb.AppendLine();

        // --- 4. Defense Evasion + Impact prep ---
        sb.AppendLine("## 4. Defense Evasion / chuẩn bị mã hoá (Ransomware Precursor)");
        if (ransom.Count == 0)
        {
            sb.AppendLine("*Không phát hiện hoạt động chuẩn bị ransomware.*");
        }
        else
        {
            foreach (var f in ransom) { AppendFinding(sb, f); }
        }
        sb.AppendLine();

        // --- 5. IOC summary table ---
        sb.AppendLine("## 5. IOC tóm tắt");
        sb.AppendLine();
        sb.AppendLine("| Loại | Giá trị |");
        sb.AppendLine("|---|---|");
        foreach (var ip in ips) { sb.AppendLine($"| IP nguồn / C2 | `{Escape(ip)}` |"); }
        foreach (var u in urls) { sb.AppendLine($"| URL payload / C2 | `{Escape(u)}` |"); }
        foreach (var e in emails) { sb.AppendLine($"| Email | `{Escape(e)}` |"); }
        foreach (var b in btc) { sb.AppendLine($"| Ví BTC | `{Escape(b)}` |"); }
        foreach (var f in files.Take(40)) { sb.AppendLine($"| File path | `{Escape(f)}` |"); }
        foreach (var o in others.Take(20)) { sb.AppendLine($"| Khác | `{Escape(o)}` |"); }
        if (ips.Count + urls.Count + emails.Count + btc.Count + files.Count + others.Count == 0)
        {
            sb.AppendLine("| — | *Không trích xuất được IOC* |");
        }
        sb.AppendLine();

        // --- 6. Recommendations ---
        sb.AppendLine("## 6. Khuyến nghị xử lý");
        sb.AppendLine();
        var allRem = ctx.AllFindings
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

        if (other.Count > 0)
        {
            sb.AppendLine("## 7. Findings khác");
            foreach (var f in other)
            {
                sb.AppendLine($"- **[{f.Severity}] {f.Title}** (`{f.Id}`)");
            }
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine($"*Báo cáo do **SecAudit** sinh tự động lúc {ctx.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", inv)}.*");
        return sb.ToString();
    }

    public static (
        List<Finding> browser, List<Finding> office, List<Finding> ad,
        List<Finding> ransom, List<Finding> recent, List<Finding> other)
        Categorise(IEnumerable<Finding> findings)
    {
        var b = new List<Finding>();
        var o = new List<Finding>();
        var a = new List<Finding>();
        var r = new List<Finding>();
        var rc = new List<Finding>();
        var ot = new List<Finding>();
        foreach (var f in findings.OrderByDescending(x => x.Severity))
        {
            if (f.Id.StartsWith("BRW-", StringComparison.Ordinal)) { b.Add(f); }
            else if (f.Id.StartsWith("OFC-", StringComparison.Ordinal)) { o.Add(f); }
            else if (f.Id.StartsWith("FOR-AD-ATTACK-", StringComparison.Ordinal)) { a.Add(f); }
            else if (f.Id.StartsWith("FOR-RANSOM-PRE-", StringComparison.Ordinal)) { r.Add(f); }
            else if (f.Id.StartsWith("RCT-", StringComparison.Ordinal)) { rc.Add(f); }
            else { ot.Add(f); }
        }
        return (b, o, a, r, rc, ot);
    }

    public static (List<string> ips, List<string> urls, List<string> emails,
                   List<string> btc, List<string> files, List<string> others)
        CategoriseIocs(IEnumerable<string> iocs)
    {
        var ips = new List<string>();
        var urls = new List<string>();
        var emails = new List<string>();
        var btc = new List<string>();
        var files = new List<string>();
        var others = new List<string>();
        foreach (var i in iocs.OrderBy(x => x, StringComparer.Ordinal))
        {
            if (i.StartsWith("ip:", StringComparison.Ordinal)) { ips.Add(i["ip:".Length..]); }
            else if (i.StartsWith("url:", StringComparison.Ordinal)) { urls.Add(i["url:".Length..]); }
            else if (i.StartsWith("email:", StringComparison.Ordinal)) { emails.Add(i["email:".Length..]); }
            else if (i.StartsWith("btc:", StringComparison.Ordinal)) { btc.Add(i["btc:".Length..]); }
            else if (i.StartsWith("file:", StringComparison.Ordinal)) { files.Add(i["file:".Length..]); }
            else { others.Add(i); }
        }
        return (ips, urls, emails, btc, files, others);
    }

    private static int Count(IEnumerable<Finding> findings, Severity sev)
        => findings.Count(f => f.Severity == sev);

    private static void AppendFinding(StringBuilder sb, Finding f)
    {
        sb.AppendLine($"#### [{f.Severity}] {f.Title}");
        sb.AppendLine();
        sb.AppendLine($"- **ID:** `{f.Id}`");
        if (f.AttackTechniqueIds.Count > 0)
        {
            sb.AppendLine($"- **MITRE ATT&CK:** {string.Join(", ", f.AttackTechniqueIds.Select(t => $"`{t}`"))}");
        }
        sb.AppendLine();
        sb.AppendLine("**Bằng chứng:**");
        sb.AppendLine();
        sb.AppendLine("```");
        sb.AppendLine(f.Evidence);
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine($"**Khuyến nghị:** {f.Remediation}");
        sb.AppendLine();
    }

    private static string Escape(string s)
        => s.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("|", "\\|", StringComparison.Ordinal);
}
