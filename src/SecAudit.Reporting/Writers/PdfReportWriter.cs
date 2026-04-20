using System.Globalization;
using QuestPDF.Drawing;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.Reporting.Writers;

/// <summary>
/// PDF render via QuestPDF (Community license). Same "BIÊN BẢN GHI NHẬN" layout as
/// the HTML writer: every metadata field in <see cref="ReportSettings"/> that is
/// populated renders as text; every empty field renders as dotted blanks so the
/// inspector can hand-fill after printing.
/// </summary>
public sealed class PdfReportWriter : IReportWriter
{
    private const string TableHeaderBg = "#E9E9E9";
    private const string KeyBg = "#F3F4F6";
    // Narrow blank widths for inline dots (ngày/tháng/năm)
    private const float BlankXs = 50f;
    private const float BlankSm = 70f;
    private const float BlankMd = 90f;

    // First-line indent = 1cm. QuestPDF does not expose true "first-line only"
    // indent, but non-breaking spaces (U+00A0) are NOT collapsed and wrap at
    // the container edge — so prefixing ~10 NBSPs at 12pt Times New Roman
    // yields a ~1cm indent only on the first visual line. Subsequent wrapped
    // lines start at the container left edge as the user requested.
    private const string FirstLineIndent = "\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0";

    static PdfReportWriter()
    {
        QuestPDF.Settings.License = LicenseType.Community;
    }

    public string Extension => "pdf";
    public string DisplayName => "PDF";

    public Task WriteAsync(ReportData data, string outputPath, CancellationToken ct)
    {
        var meta = data.Metadata;
        var gen = data.GeneratedAt.LocalDateTime;
        bool autoDate = meta.AutoDate;

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                // Lề theo yêu cầu nghiệp vụ: trái 3cm, phải 2cm, trên/dưới 2cm.
                page.MarginLeft(3, Unit.Centimetre);
                page.MarginRight(2, Unit.Centimetre);
                page.MarginTop(2, Unit.Centimetre);
                page.MarginBottom(2, Unit.Centimetre);
                page.DefaultTextStyle(t => t.FontSize(12).FontFamily("Times New Roman"));

                page.Content().Column(col =>
                {
                    // ===== Top header: 2 cột (tỉ lệ 1:2 để khối phải căn tại ~3/5 chiều ngang A4) =====
                    col.Item().Row(row =>
                    {
                        // LEFT: đơn vị chủ quản — 2 dòng theo chuẩn biên bản Công an VN:
                        //   Dòng 1 (đơn vị cấp trên): Times New Roman 13pt, in thường (không đậm)
                        //   Dòng 2 (đơn vị cấp dưới): Times New Roman 13pt, in hoa đậm
                        // Dưới dòng 2 có gạch ngang ngắn ("kẻ chân") là nét liền — giữ nguyên.
                        // Các dòng trống không dùng gạch liền mà dùng CHUỖI DẤU CHẤM giống hệt
                        // Mau 1.pdf để người dùng điền tay sau khi in.
                        row.RelativeItem(1).PaddingRight(20).Column(c =>
                        {
                            bool hasL1 = !string.IsNullOrWhiteSpace(meta.OrgLine1);
                            bool hasL2 = !string.IsNullOrWhiteSpace(meta.OrgLine2);

                            if (hasL1)
                            {
                                c.Item().AlignCenter().Text(meta.OrgLine1).FontSize(13);
                            }
                            else
                            {
                                // Dòng chấm (không phải nét liền) — khớp Mau 1.pdf
                                c.Item().AlignCenter().Text(new string('.', 42))
                                    .FontSize(11).FontColor(Colors.Grey.Darken1);
                            }

                            if (hasL2)
                            {
                                // Auto-uppercase để admin gõ "Tổ kiểm tra" hay "TỔ KIỂM TRA" đều đúng format.
                                var upper = meta.OrgLine2.ToUpper(System.Globalization.CultureInfo.CurrentCulture);
                                c.Item().AlignCenter().Text(upper).Bold().FontSize(13);
                            }
                            else
                            {
                                c.Item().PaddingTop(2).AlignCenter().Text(new string('.', 42))
                                    .FontSize(11).FontColor(Colors.Grey.Darken1);
                            }

                            // "Kẻ chân" ngắn — NÉT LIỀN, đúng như mẫu
                            c.Item().PaddingTop(3).AlignCenter().Container().Width(60).LineHorizontal(1).LineColor(Colors.Black);
                        });
                        // RIGHT: Quốc hiệu — cùng cỡ 13pt bold, "Độc lập" dùng underline tích hợp.
                        // Dòng "<địa danh>, ngày ... tháng ... năm ..." đặt NGAY dưới motto
                        // trong cùng ô phải để đảm bảo hiển thị 1 dòng, căn giữa.
                        row.RelativeItem(2).Column(c =>
                        {
                            c.Item().AlignCenter().Text("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM").Bold().FontSize(13);
                            c.Item().AlignCenter().Text(t =>
                            {
                                t.DefaultTextStyle(s => s.Bold().FontSize(13).Underline());
                                t.Span("Độc lập – Tự do – Hạnh phúc");
                            });
                            c.Item().PaddingTop(4).AlignCenter().Text(t =>
                            {
                                t.DefaultTextStyle(s => s.Italic().FontSize(12));
                                if (!string.IsNullOrWhiteSpace(meta.Place))
                                {
                                    t.Span(meta.Place);
                                }
                                else
                                {
                                    // Địa danh mặc định ngắn hơn (60pt thay vì 90pt) để
                                    // tổng dòng vẫn vừa trong ô phải, không bị wrap.
                                    BlankInline(t, 60f);
                                }
                                t.Span(", ngày ");
                                DateSpan(t, autoDate, autoDate ? gen.Day.ToString("D2", CultureInfo.InvariantCulture) : null, 30f);
                                t.Span(" tháng ");
                                DateSpan(t, autoDate, autoDate ? gen.Month.ToString("D2", CultureInfo.InvariantCulture) : null, 30f);
                                t.Span(" năm ");
                                DateSpan(t, autoDate, autoDate ? gen.Year.ToString(CultureInfo.InvariantCulture) : null, 40f);
                            });
                        });
                    });

                    // ===== Title =====
                    col.Item().PaddingTop(10).AlignCenter().Text("BIÊN BẢN GHI NHẬN")
                        .Bold().FontSize(16);
                    // Subtitle KHÔNG gạch chân — user yêu cầu bỏ underline vì
                    // khi in ra giấy nét underline chạm vào dấu chấm của chữ "ỉ/ị"
                    // phía dưới gây rối mắt.
                    col.Item().PaddingTop(2).AlignCenter().Text(t =>
                    {
                        t.DefaultTextStyle(s => s.Bold().FontSize(13));
                        t.Span("Kết quả kiểm tra việc đảm bảo an ninh mạng, an toàn thông tin");
                    });

                    // ===== Căn cứ kiểm tra =====
                    col.Item().PaddingTop(14).Text("Căn cứ kiểm tra:").Bold();
                    if (!string.IsNullOrWhiteSpace(meta.LegalBasis))
                    {
                        foreach (var line in SplitLines(meta.LegalBasis))
                        {
                            // First-line 1cm indent qua NBSP-prefix; dòng wrap sau đó
                            // quay về lề trái.
                            col.Item().PaddingTop(2).Text(FirstLineIndent + line);
                        }
                    }
                    else
                    {
                        BlankLine(col); BlankLine(col); BlankLine(col);
                    }

                    // ===== Hồi … giờ … phút, ngày …, tại: =====
                    col.Item().PaddingTop(8).Text(t =>
                    {
                        t.Span(FirstLineIndent);
                        t.Span("Hồi ");
                        DateSpan(t, autoDate, autoDate ? gen.Hour.ToString("D2", CultureInfo.InvariantCulture) : null, BlankXs);
                        t.Span(" giờ ");
                        DateSpan(t, autoDate, autoDate ? gen.Minute.ToString("D2", CultureInfo.InvariantCulture) : null, BlankXs);
                        t.Span(" phút, ngày ");
                        DateSpan(t, autoDate, autoDate ? gen.Day.ToString(CultureInfo.InvariantCulture) : null, BlankXs);
                        t.Span(" tháng ");
                        DateSpan(t, autoDate, autoDate ? gen.Month.ToString(CultureInfo.InvariantCulture) : null, BlankXs);
                        t.Span(" năm ");
                        DateSpan(t, autoDate, autoDate ? gen.Year.ToString(CultureInfo.InvariantCulture) : null, BlankSm);
                        t.Span(", tại:");
                    });
                    if (!string.IsNullOrWhiteSpace(meta.InspectionLocation))
                    {
                        foreach (var line in SplitLines(meta.InspectionLocation))
                        {
                            col.Item().PaddingTop(2).Text(FirstLineIndent + line);
                        }
                    }
                    else
                    {
                        BlankLine(col); BlankLine(col);
                    }

                    // ===== I. THÀNH PHẦN =====
                    col.Item().PaddingTop(10).Text("I. Thành phần").Bold().FontSize(13);
                    col.Item().PaddingTop(6).Text("1. Tổ kiểm tra").Bold();
                    if (!string.IsNullOrWhiteSpace(meta.InspectionTeam))
                    {
                        foreach (var line in SplitLines(meta.InspectionTeam))
                        {
                            col.Item().PaddingTop(2).Text(FirstLineIndent + line);
                        }
                    }
                    else
                    {
                        BlankLine(col); BlankLine(col); BlankLine(col); BlankLine(col); BlankLine(col);
                    }

                    col.Item().PaddingTop(6).Text("2. Đơn vị có phương tiện, thiết bị được kiểm tra:").Bold();
                    if (!string.IsNullOrWhiteSpace(meta.AuditedUnitDetail))
                    {
                        foreach (var line in SplitLines(meta.AuditedUnitDetail))
                        {
                            col.Item().PaddingTop(2).Text(FirstLineIndent + line);
                        }
                    }
                    else
                    {
                        BlankLine(col); BlankLine(col); BlankLine(col);
                    }

                    // ===== II. KẾT QUẢ KIỂM TRA (dữ liệu thực) =====
                    col.Item().PaddingTop(12).Text("II. Kết quả kiểm tra").Bold().FontSize(13);

                    col.Item().PaddingTop(6).Text("1. Thông tin thiết bị kiểm tra").Bold();
                    col.Item().PaddingTop(4).Table(t =>
                    {
                        t.ColumnsDefinition(c => { c.ConstantColumn(160); c.RelativeColumn(); });
                        Kv(t, "Tên máy tính", data.Device.ComputerName);
                        Kv(t, "CPU", data.Device.Cpu);
                        Kv(t, "Serial Number BIOS", data.Device.BiosSerial);
                        Kv(t, "RAM", data.Device.TotalRam);
                        Kv(t, "Hệ điều hành", data.Device.OperatingSystem);
                        var nicText = data.Device.NetworkAddresses.Count == 0
                            ? "(không phát hiện giao tiếp mạng đang hoạt động)"
                            : string.Join("\n", data.Device.NetworkAddresses.Select(n =>
                                $"{n.InterfaceName} — MAC {n.MacAddress} — IPv4 {n.IPv4}"
                                + (string.IsNullOrEmpty(n.IPv6) ? "" : $" — IPv6 {n.IPv6}")));
                        Kv(t, "Địa chỉ MAC / IP", nicText);
                    });

                    int idx = 2;
                    if (data.TotalFindings == 0 && data.ByModule.Count == 0)
                    {
                        col.Item().PaddingTop(6).Text(FirstLineIndent
                            + "Không phát hiện vấn đề nào. Hệ thống đang ở trạng thái tốt.")
                            .Italic().FontColor(Colors.Grey.Darken2);
                    }
                    else
                    {
                        foreach (var (moduleId, findings) in data.ByModule)
                        {
                            var viName = ModuleNameTranslator.Translate(moduleId);
                            col.Item().PaddingTop(8).Text($"{idx}. {viName} — {findings.Count} phát hiện").Bold();
                            if (findings.Count == 0)
                            {
                                col.Item().Text("Không có phát hiện nào ở module này.")
                                    .Italic().FontColor(Colors.Grey.Darken2).FontSize(10);
                            }
                            else
                            {
                                col.Item().PaddingTop(2).Table(t =>
                                {
                                    t.ColumnsDefinition(c =>
                                    {
                                        c.ConstantColumn(45);
                                        c.ConstantColumn(85);
                                        c.RelativeColumn(2);
                                        c.RelativeColumn(3);
                                        c.RelativeColumn(2);
                                    });
                                    t.Header(h =>
                                    {
                                        Th(h, "Mức"); Th(h, "Mã"); Th(h, "Tiêu đề"); Th(h, "Bằng chứng"); Th(h, "Khuyến nghị");
                                    });
                                    foreach (var f in findings.OrderByDescending(x => (int)x.Severity))
                                    {
                                        Td(t).Text(f.Severity.ToString())
                                            .FontColor(SeverityColor(f.Severity.ToString())).Bold().FontSize(9);
                                        Td(t).Text(f.Id).FontSize(8).FontColor(Colors.Grey.Darken3);
                                        Td(t).Text(f.Title).FontSize(9);
                                        Td(t).Text(f.Evidence).FontSize(8).FontColor(Colors.Grey.Darken3);
                                        Td(t).Text(f.Remediation).FontSize(9);
                                    }
                                });
                            }
                            idx++;
                        }
                    }

                    if (data.AppliedActions.Count > 0)
                    {
                        col.Item().PaddingTop(8).Text($"{idx}. Nội dung đã xử lý khắc phục").Bold();
                        col.Item().PaddingTop(2).Table(t =>
                        {
                            t.ColumnsDefinition(c =>
                            {
                                c.ConstantColumn(85); c.RelativeColumn(2); c.ConstantColumn(60);
                                c.RelativeColumn(3); c.ConstantColumn(60); c.ConstantColumn(60);
                            });
                            t.Header(h =>
                            {
                                Th(h, "Mã lỗi"); Th(h, "Hành động"); Th(h, "Kết quả");
                                Th(h, "Chi tiết"); Th(h, "Cần reboot?"); Th(h, "Thời điểm");
                            });
                            foreach (var a in data.AppliedActions)
                            {
                                Td(t).Text(a.FindingId).FontSize(8);
                                Td(t).Text(a.ActionTitle).FontSize(9);
                                Td(t).Text(a.Succeeded ? "Thành công" : "Thất bại")
                                    .FontColor(a.Succeeded ? Colors.Green.Darken2 : Colors.Red.Darken1).Bold().FontSize(9);
                                Td(t).Text(a.Message).FontSize(8);
                                Td(t).Text(a.RebootRequired ? "Có" : "Không").FontSize(9);
                                Td(t).Text(a.AppliedAt.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture))
                                    .FontSize(8);
                            }
                        });
                        idx++;
                    }

                    if (data.Recommendations.Count > 0)
                    {
                        col.Item().PaddingTop(8).Text($"{idx}. Khuyến nghị").Bold();
                        col.Item().PaddingTop(2).Table(t =>
                        {
                            t.ColumnsDefinition(c =>
                            {
                                c.ConstantColumn(45); c.ConstantColumn(85); c.RelativeColumn(2); c.RelativeColumn(4);
                            });
                            t.Header(h =>
                            {
                                Th(h, "Mức"); Th(h, "Mã"); Th(h, "Tiêu đề"); Th(h, "Hướng dẫn khắc phục");
                            });
                            foreach (var r in data.Recommendations)
                            {
                                Td(t).Text(r.Severity).FontColor(SeverityColor(r.Severity)).Bold().FontSize(9);
                                Td(t).Text(r.FindingId).FontSize(8).FontColor(Colors.Grey.Darken3);
                                Td(t).Text(r.Title).FontSize(9);
                                Td(t).Text(r.Guidance).FontSize(9);
                            }
                        });
                    }

                    // ===== Closing — always dots (end time filled at signing) =====
                    col.Item().PaddingTop(16).Text(t =>
                    {
                        t.Span(FirstLineIndent);
                        t.Span("Biên bản kết thúc hồi ");
                        BlankInline(t, BlankXs);
                        t.Span(" giờ ");
                        BlankInline(t, BlankXs);
                        t.Span(" phút cùng ngày; đã thông qua các bên cùng nhất trí và ký tên dưới đây./.");
                    });

                    // ===== 2×2 signature grid =====
                    col.Item().PaddingTop(16).Row(row =>
                    {
                        SignatureCell(row, "ĐẠI DIỆN\nĐƠN VỊ ĐƯỢC KIỂM TRA", meta.AuditedUnit);
                        SignatureCell(row, "TỔ TRƯỞNG\nTỔ KIỂM TRA", meta.TeamLeader);
                    });
                    col.Item().PaddingTop(80).Row(row =>
                    {
                        SignatureCell(row, "CÁN BỘ THAM GIA", meta.TeamMember);
                        SignatureCell(row, "CÁN BỘ LẬP BIÊN BẢN", meta.Recorder);
                    });
                    col.Item().PaddingTop(60); // spacer cho chữ ký cặp cuối
                });

                page.Footer().AlignCenter().Text(t =>
                {
                    t.Span("SecAudit · Trang ").FontSize(8).FontColor(Colors.Grey.Medium);
                    t.CurrentPageNumber().FontSize(8).FontColor(Colors.Grey.Medium);
                    t.Span(" / ").FontSize(8).FontColor(Colors.Grey.Medium);
                    t.TotalPages().FontSize(8).FontColor(Colors.Grey.Medium);
                });
            });
        }).GeneratePdf(outputPath);

        return Task.CompletedTask;
    }

    // -------- helpers --------

    /// <summary>
    /// Full-width DOTTED blank line matching Mau 1.pdf.
    /// Cắt số dấu chấm xuống ~145 để chắc chắn fit 1 dòng (16cm content width
    /// ở A4 với lề 3/2cm, Times New Roman 11pt "." ≈ 2.8pt). 170 dots trước
    /// đây bị wrap xuống dòng tạo 6 chấm lẻ rất xấu. Dùng Container.MinHeight
    /// để khoá chiều cao và ShrinkIfNeeded không giúp ở đây vì Text tự wrap.
    /// </summary>
    private static void BlankLine(ColumnDescriptor col)
    {
        // DashSmall = 145 chars × 2.8pt ≈ 406pt < 453pt content width → fit
        // trong 1 dòng ở mọi PDF renderer. Trước đây dùng 170 gây wrap.
        col.Item().PaddingTop(3).Text(new string('.', 145))
            .FontSize(11).FontColor(Colors.Grey.Darken1);
    }

    /// <summary>
    /// Inline blank "___" of fixed width used in phrases like "ngày __ tháng __".
    /// Implemented as underscore-like dots using a constant-width padded string since
    /// QuestPDF TextDescriptor spans can't draw arbitrary geometry.
    /// </summary>
    private static void BlankInline(TextDescriptor t, float widthPx)
    {
        // Approx 7 dots per 20px at 12pt Times New Roman.
        int dotCount = (int)Math.Round(widthPx / 3.0f);
        if (dotCount < 4)
        {
            dotCount = 4;
        }
        t.Span(new string('.', dotCount)).FontColor(Colors.Grey.Darken1);
    }

    /// <summary>
    /// Renders either a value (when <paramref name="filled"/> is true and value non-null)
    /// or an inline dotted blank of width <paramref name="blankWidth"/>.
    /// </summary>
    private static void DateSpan(TextDescriptor t, bool filled, string? value, float blankWidth)
    {
        if (filled && !string.IsNullOrEmpty(value))
        {
            t.Span(value);
        }
        else
        {
            BlankInline(t, blankWidth);
        }
    }

    /// <summary>
    /// Split a multiline textarea value into trimmed lines; blank leading/trailing
    /// lines dropped. Internal blank lines kept so user-controlled spacing survives.
    /// </summary>
    private static string[] SplitLines(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }
        var normalized = value.Replace("\r\n", "\n").Replace('\r', '\n');
        var parts = normalized.Split('\n');
        int start = 0;
        int end = parts.Length - 1;
        while (start <= end && string.IsNullOrWhiteSpace(parts[start])) { start++; }
        while (end >= start && string.IsNullOrWhiteSpace(parts[end])) { end--; }
        if (start > end)
        {
            return Array.Empty<string>();
        }
        var result = new string[end - start + 1];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = parts[start + i];
        }
        return result;
    }

    private static void Kv(TableDescriptor t, string key, string value)
    {
        t.Cell().Border(0.5f).BorderColor(Colors.Grey.Darken1).Background(KeyBg).Padding(4)
            .Text(key).Bold().FontSize(10);
        t.Cell().Border(0.5f).BorderColor(Colors.Grey.Darken1).Padding(4)
            .Text(value).FontSize(10);
    }

    private static void Th(TableCellDescriptor h, string text)
    {
        h.Cell().Background(TableHeaderBg).Border(0.5f).BorderColor(Colors.Grey.Darken1).Padding(3)
            .AlignCenter().Text(text).FontSize(9).Bold();
    }

    private static IContainer Td(TableDescriptor t)
        => t.Cell().Border(0.5f).BorderColor(Colors.Grey.Darken1).Padding(3);

    private static void SignatureCell(RowDescriptor row, string role, string signerName)
    {
        row.RelativeItem().Column(c =>
        {
            c.Item().AlignCenter().Text(role).Bold().FontSize(12);
            if (!string.IsNullOrWhiteSpace(signerName))
            {
                c.Item().PaddingTop(72).AlignCenter().Text(signerName).Bold().FontSize(12);
            }
        });
    }

    private static string SeverityColor(string sev) => sev switch
    {
        "Critical" => Colors.Red.Darken1,
        "High" => Colors.Orange.Darken2,
        "Medium" => Colors.Yellow.Darken3,
        "Low" => Colors.Green.Darken1,
        "Info" => Colors.Grey.Darken1,
        _ => Colors.Grey.Darken1
    };
}
