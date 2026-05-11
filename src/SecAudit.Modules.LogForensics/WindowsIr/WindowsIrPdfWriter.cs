using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.WindowsIr;

/// <summary>
/// Renders the unified Windows IR report as a printable PDF (A4 portrait,
/// 6 sections + finding cards + IOC table). Mirrors LinuxIncidentPdfWriter
/// styling so analysts get a consistent look across OS-specific reports.
/// </summary>
public static class WindowsIrPdfWriter
{
    static WindowsIrPdfWriter()
    {
        QuestPDF.Settings.License = LicenseType.Community;
    }

    public static byte[] Render(WindowsIrReportBuilder.ReportContext ctx)
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
                    t.Span("SecAudit Windows IR · ");
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

    private static Action<IContainer> BuildHeader(WindowsIrReportBuilder.ReportContext ctx)
        => container => container.Column(col =>
        {
            col.Item().Text($"BÁO CÁO ĐIỀU TRA WINDOWS IR — {ctx.Asset}")
                .FontSize(18).Bold().FontColor(Colors.Blue.Darken3);
            col.Item().PaddingTop(2).LineHorizontal(1).LineColor(Colors.Blue.Darken3);
            col.Item().PaddingTop(6).Text(t =>
            {
                t.Span("Asset: ").Bold(); t.Span(ctx.Asset); t.Span("    ");
                t.Span("Nguồn: ").Bold(); t.Span(Truncate(ctx.SourcePath, 90));
            });
        });

    private static void BuildBody(IContainer container, WindowsIrReportBuilder.ReportContext ctx)
    {
        var (browser, office, ad, ransom, recent, _) = WindowsIrReportBuilder.Categorise(ctx.AllFindings);
        var (ips, urls, emails, btc, files, others) = WindowsIrReportBuilder.CategoriseIocs(ctx.ExtractedIocs);

        container.PaddingTop(10).Column(col =>
        {
            col.Spacing(10);

            // Summary
            col.Item().Background(Colors.Grey.Lighten4).Padding(8).Column(s =>
            {
                s.Item().Text("Tổng quan").Bold().FontSize(12);
                s.Item().Text($"Tệp/profile đã quét: {ctx.FilesScanned:N0}");
                s.Item().Text($"Tổng số finding: {ctx.AllFindings.Count}  ·  "
                            + $"Critical: {Count(ctx.AllFindings, Severity.Critical)}  ·  "
                            + $"High: {Count(ctx.AllFindings, Severity.High)}  ·  "
                            + $"Medium: {Count(ctx.AllFindings, Severity.Medium)}");
                s.Item().Text($"Tổng số IOC: {ctx.ExtractedIocs.Count}");
            });

            // Section 1
            Section(col, "1. Initial Access — phishing / drive-by / Office attachment");
            if (browser.Count == 0 && office.Count == 0)
            {
                NoResult(col);
            }
            else
            {
                if (office.Count > 0)
                {
                    SubSection(col, "1a. Office & Outlook attachment");
                    foreach (var f in office) { FindingCard(col, f); }
                }
                if (browser.Count > 0)
                {
                    SubSection(col, "1b. Browser history & downloads");
                    foreach (var f in browser) { FindingCard(col, f); }
                }
            }

            // Section 2
            Section(col, "2. User Execution — file đã mở gần đây / USB / LNK dropper");
            if (recent.Count == 0) { NoResult(col); }
            else { foreach (var f in recent) { FindingCard(col, f); } }

            // Section 3
            Section(col, "3. Credential Access — AD attack");
            if (ad.Count == 0) { NoResult(col); }
            else { foreach (var f in ad) { FindingCard(col, f); } }

            // Section 4
            Section(col, "4. Defense Evasion / chuẩn bị mã hoá");
            if (ransom.Count == 0) { NoResult(col); }
            else { foreach (var f in ransom) { FindingCard(col, f); } }

            // Section 5 — IOC table
            Section(col, "5. IOC tóm tắt");
            col.Item().Table(t =>
            {
                t.ColumnsDefinition(cd => { cd.RelativeColumn(1); cd.RelativeColumn(3); });
                t.Header(h =>
                {
                    h.Cell().Background(Colors.Blue.Lighten3).Padding(4).Text("Loại").Bold();
                    h.Cell().Background(Colors.Blue.Lighten3).Padding(4).Text("Giá trị").Bold();
                });
                foreach (var ip in ips) { Row(t, "IP nguồn / C2", ip); }
                foreach (var u in urls) { Row(t, "URL payload / C2", u); }
                foreach (var e in emails) { Row(t, "Email", e); }
                foreach (var b in btc) { Row(t, "Ví BTC", b); }
                foreach (var f in files.Take(40)) { Row(t, "File path", f); }
                foreach (var o in others.Take(20)) { Row(t, "Khác", o); }
                if (ips.Count + urls.Count + emails.Count + btc.Count + files.Count + others.Count == 0)
                {
                    Row(t, "—", "Không trích xuất được IOC");
                }
            });

            // Section 6 — Recommendations
            Section(col, "6. Khuyến nghị xử lý");
            var recs = ctx.AllFindings
                .Where(f => f.Severity >= Severity.Medium)
                .Select(f => f.Remediation)
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            if (recs.Count == 0) { NoResult(col); }
            else
            {
                var i = 1;
                foreach (var r in recs) { col.Item().Text($"{i++}. {r}"); }
            }
        });
    }

    private static void Section(ColumnDescriptor col, string title)
    {
        col.Item().PaddingTop(8).Text(title).FontSize(13).Bold().FontColor(Colors.Blue.Darken3);
        col.Item().LineHorizontal(0.5f).LineColor(Colors.Blue.Lighten2);
    }

    private static void SubSection(ColumnDescriptor col, string title)
        => col.Item().PaddingTop(4).Text(title).FontSize(11).Bold().FontColor(Colors.Grey.Darken3);

    private static void NoResult(ColumnDescriptor col)
        => col.Item().Text("Không phát hiện sự kiện trong nhóm này.")
            .Italic().FontColor(Colors.Grey.Darken1);

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

    private static void Row(TableDescriptor t, string label, string value)
    {
        t.Cell().Border(0.3f).BorderColor(Colors.Grey.Lighten1).Padding(3).Text(label).FontSize(9);
        t.Cell().Border(0.3f).BorderColor(Colors.Grey.Lighten1).Padding(3)
            .Text(value).FontFamily("Consolas").FontSize(9);
    }

    private static int Count(IEnumerable<Finding> findings, Severity sev)
        => findings.Count(f => f.Severity == sev);

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
