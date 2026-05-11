using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Renders the same 6-section IR report that
/// <see cref="LinuxIncidentReportBuilder"/> produces in Markdown/HTML, but as a
/// printable PDF using QuestPDF. PDF is the format SOC managers and auditors
/// usually need for ticket attachments / chain-of-custody packages.
///
/// <para>Layout: A4 portrait, 14pt headings, 9.5pt monospace evidence blocks,
/// page footer with timestamp + page number for evidentiary integrity.</para>
/// </summary>
public static class LinuxIncidentPdfWriter
{
    static LinuxIncidentPdfWriter()
    {
        // Community licence — required by QuestPDF 2024.x. We're an open-source
        // forensic tool, no paid distribution.
        QuestPDF.Settings.License = LicenseType.Community;
    }

    public static byte[] Render(LinuxIncidentReportBuilder.ReportContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        var doc = Document.Create(c =>
        {
            c.Page(p =>
            {
                p.Size(PageSizes.A4);
                p.Margin(28);
                p.PageColor(Colors.White);
                p.DefaultTextStyle(t => t.FontSize(10).FontFamily("Segoe UI"));

                p.Header().Element(BuildHeader(ctx));
                p.Content().Element(c2 => BuildBody(c2, ctx));
                p.Footer().AlignCenter().Text(t =>
                {
                    t.Span("SecAudit · ");
                    t.Span(ctx.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"));
                    t.Span(" · trang ");
                    t.CurrentPageNumber();
                    t.Span(" / ");
                    t.TotalPages();
                });
            });
        });
        return doc.GeneratePdf();
    }

    private static Action<IContainer> BuildHeader(LinuxIncidentReportBuilder.ReportContext ctx)
        => container => container.Column(col =>
        {
            col.Item().Text($"BÁO CÁO ĐIỀU TRA SỰ CỐ — {ctx.Asset}")
                .FontSize(18).Bold().FontColor(Colors.Red.Darken2);
            col.Item().PaddingTop(2).LineHorizontal(1).LineColor(Colors.Red.Darken2);
            col.Item().PaddingTop(6).Text(t =>
            {
                t.Span("Asset: ").Bold(); t.Span(ctx.Asset); t.Span("    ");
                t.Span("Nguồn: ").Bold(); t.Span(Truncate(ctx.SourcePath, 90));
            });
        });

    private static void BuildBody(IContainer container, LinuxIncidentReportBuilder.ReportContext ctx)
    {
        var (ssh, sudo, cron, ransom, encExt, _, _) = Categorise(ctx.Result.Findings);
        var (ips, urls, emails, btc, others) = CategoriseIocs(ctx.Result.ExtractedIocs);

        container.PaddingTop(10).Column(col =>
        {
            col.Spacing(10);

            // Summary box
            col.Item().Background(Colors.Grey.Lighten4).Padding(8).Column(s =>
            {
                s.Item().Text("Tổng quan").Bold().FontSize(12);
                s.Item().Text($"Tệp đã quét: {ctx.Result.FilesScanned:N0}");
                s.Item().Text($"Tổng số finding: {ctx.Result.Findings.Count}  ·  "
                            + $"Critical: {Count(ctx.Result.Findings, Severity.Critical)}  ·  "
                            + $"High: {Count(ctx.Result.Findings, Severity.High)}  ·  "
                            + $"Medium: {Count(ctx.Result.Findings, Severity.Medium)}");
                s.Item().Text($"Tổng số IOC: {ctx.Result.ExtractedIocs.Count}");
            });

            // Section 1 — Timeline
            Section(col, "1. Dòng thời gian & dấu vết truy cập");
            if (ssh.Count == 0)
            {
                col.Item().Text("Không phát hiện sự kiện SSH bất thường trong auth.log.")
                    .Italic().FontColor(Colors.Grey.Darken1);
            }
            else
            {
                foreach (var f in ssh)
                {
                    FindingCard(col, f);
                }
            }

            // Section 2 — Privilege escalation
            Section(col, "2. Đánh giá leo thang đặc quyền (sudoers)");
            if (sudo.Count == 0)
            {
                col.Item().Text("Không phát hiện cấu hình sudoers nguy hiểm.")
                    .Italic().FontColor(Colors.Grey.Darken1);
            }
            else
            {
                foreach (var f in sudo) { FindingCard(col, f); }
            }

            // Section 3 — Payload + crypto
            Section(col, "3. Payload & cấu hình mã hoá");
            if (ransom.Count == 0 && encExt.Count == 0)
            {
                col.Item().Text("Không phát hiện ransom note hay chuỗi file mã hoá.")
                    .Italic().FontColor(Colors.Grey.Darken1);
            }
            else
            {
                foreach (var f in ransom) { FindingCard(col, f); }
                foreach (var f in encExt) { FindingCard(col, f); }
            }

            // Section 4 — Persistence
            Section(col, "4. Persistence (cron / scheduled)");
            if (cron.Count == 0)
            {
                col.Item().Text("Không phát hiện cron persistence đáng ngờ.")
                    .Italic().FontColor(Colors.Grey.Darken1);
            }
            else
            {
                foreach (var f in cron) { FindingCard(col, f); }
            }

            // Section 5 — IOC summary
            Section(col, "5. IOC tóm tắt");
            col.Item().Table(t =>
            {
                t.ColumnsDefinition(cd => { cd.RelativeColumn(1); cd.RelativeColumn(3); });
                t.Header(h =>
                {
                    h.Cell().Background(Colors.Blue.Lighten3).Padding(4).Text("Loại").Bold();
                    h.Cell().Background(Colors.Blue.Lighten3).Padding(4).Text("Giá trị").Bold();
                });
                foreach (var ip in ips) { IocRow(t, "IP nguồn / C2", ip); }
                foreach (var u in urls) { IocRow(t, "URL payload / C2", u); }
                foreach (var e in emails) { IocRow(t, "Email tống tiền", e); }
                foreach (var b in btc) { IocRow(t, "Ví BTC", b); }
                foreach (var o in others) { IocRow(t, "Khác", o); }
                if (ips.Count + urls.Count + emails.Count + btc.Count + others.Count == 0)
                {
                    IocRow(t, "—", "Không trích xuất được IOC");
                }
            });

            // Section 6 — Recommendations
            Section(col, "6. Khuyến nghị xử lý");
            var recs = ctx.Result.Findings
                .Where(f => f.Severity >= Severity.Medium)
                .Select(f => f.Remediation)
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            if (recs.Count == 0)
            {
                col.Item().Text("Không có khuyến nghị mức Medium+ trong phiên này.")
                    .Italic().FontColor(Colors.Grey.Darken1);
            }
            else
            {
                var i = 1;
                foreach (var r in recs)
                {
                    col.Item().Text($"{i++}. {r}");
                }
            }
        });
    }

    private static void Section(ColumnDescriptor col, string title)
    {
        col.Item().PaddingTop(8).Text(title)
            .FontSize(13).Bold().FontColor(Colors.Blue.Darken3);
        col.Item().LineHorizontal(0.5f).LineColor(Colors.Blue.Lighten2);
    }

    private static void FindingCard(ColumnDescriptor col, Finding f)
    {
        col.Item().Border(0.5f).BorderColor(Colors.Grey.Lighten1).Padding(6).Column(c =>
        {
            c.Item().Text(t =>
            {
                t.Span($"[{f.Severity}] ").Bold()
                    .FontColor(f.Severity switch
                    {
                        Severity.Critical => Colors.Red.Darken3,
                        Severity.High => Colors.Red.Medium,
                        Severity.Medium => Colors.Orange.Darken1,
                        _ => Colors.Grey.Darken1
                    });
                t.Span(f.Title).Bold();
            });
            c.Item().PaddingTop(2).Text($"ID: {f.Id}").FontSize(8).FontColor(Colors.Grey.Darken1);
            if (f.AttackTechniqueIds.Count > 0)
            {
                c.Item().Text("ATT&CK: " + string.Join(", ", f.AttackTechniqueIds))
                    .FontSize(8).FontColor(Colors.Blue.Darken1);
            }
            c.Item().PaddingTop(3).Background(Colors.Grey.Lighten4).Padding(4)
                .Text(f.Evidence).FontFamily("Consolas").FontSize(8.5f);
            c.Item().PaddingTop(3).Text(t =>
            {
                t.Span("Khuyến nghị: ").Bold();
                t.Span(f.Remediation).FontSize(9);
            });
        });
    }

    private static void IocRow(TableDescriptor t, string label, string value)
    {
        t.Cell().Border(0.3f).BorderColor(Colors.Grey.Lighten1).Padding(3).Text(label).FontSize(9);
        t.Cell().Border(0.3f).BorderColor(Colors.Grey.Lighten1).Padding(3)
            .Text(value).FontFamily("Consolas").FontSize(9);
    }

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
        foreach (var f in findings.OrderByDescending(x => x.Severity))
        {
            if (f.Id.StartsWith("LIN-SSH-", StringComparison.Ordinal)
                || f.Id.StartsWith("FOR-SSH-", StringComparison.Ordinal))
            {
                ssh.Add(f);
            }
            else if (f.Id.StartsWith("LIN-SUDOERS-", StringComparison.Ordinal)
                || f.Id.StartsWith("FOR-PRIVESC-", StringComparison.Ordinal))
            {
                sudo.Add(f);
            }
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

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";
}
