using System.Globalization;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using SecAudit.Core.Services;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.Reporting.Writers;

/// <summary>
/// Xuất .docx theo mẫu "BIÊN BẢN GHI NHẬN" chuẩn Công an Việt Nam (đã khớp Mau 2.docx
/// user cung cấp). Dùng DocumentFormat.OpenXml (managed, single-file compatible).
///
/// Mọi paragraph/run đều dùng Times New Roman 13pt (trừ tiêu đề 16pt). Dòng đơn vị
/// trên trái: dòng 1 regular, dòng 2 in hoa đậm — đúng yêu cầu nghiệp vụ.
///
/// Các trường metadata trống sẽ render thành dấu chấm "……" để người dùng điền tay
/// sau khi in (nhất quán với HTML/PDF writer).
/// </summary>
public sealed class DocxReportWriter : IReportWriter
{
    // OpenXml fontsize đơn vị = nửa-point: 13pt = "26", 16pt = "32"
    private const string FsNormal = "26";   // 13pt
    private const string FsTitle = "32";    // 16pt
    private const string FontName = "Times New Roman";

    public string Extension => "docx";
    public string DisplayName => "DOCX (Word)";

    public Task WriteAsync(ReportData data, string outputPath, CancellationToken ct)
    {
        using (var doc = WordprocessingDocument.Create(outputPath, WordprocessingDocumentType.Document))
        {
            var main = doc.AddMainDocumentPart();
            main.Document = new Document();
            var body = main.Document.AppendChild(new Body());

            WritePageSetup(body);
            WriteTopHeader(body, data);
            WriteTitle(body);
            WriteLegalBasis(body, data);
            WriteTimeLocation(body, data);
            WriteParticipants(body, data);
            WriteResults(body, data);
            WriteClosing(body);
            WriteSignatures(body, data);
        }
        return Task.CompletedTask;
    }

    // ============ Page setup ============
    private static void WritePageSetup(Body body)
    {
        // A4 portrait (11906 x 16838 twips).
        // Lề theo yêu cầu nghiệp vụ: trái 3cm, phải 2cm, trên 2cm, dưới 2cm.
        // 1 cm = 567 twips → 2cm = 1134, 3cm = 1701.
        var sectionProps = new SectionProperties(
            new PageSize { Width = 11906, Height = 16838 },
            new PageMargin
            {
                Top = 1134,      // 2cm
                Bottom = 1134,   // 2cm
                Left = 1701,     // 3cm
                Right = 1134,    // 2cm
                Header = 720,
                Footer = 720,
                Gutter = 0
            });
        body.AppendChild(sectionProps);
    }

    // ============ Top header (2 cột) ============
    private static void WriteTopHeader(Body body, ReportData data)
    {
        var m = data.Metadata;

        // Bảng 2 cột không viền — tỉ lệ 1:2 để khối phải (CỘNG HÒA) căn giữa tại
        // ~3/5 chiều ngang A4 đúng mẫu Công an VN.
        var tbl = new Table();
        tbl.AppendChild(new TableProperties(
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct },
            new TableLayout { Type = TableLayoutValues.Fixed },
            new TableBorders(
                new TopBorder { Val = BorderValues.Nil },
                new BottomBorder { Val = BorderValues.Nil },
                new LeftBorder { Val = BorderValues.Nil },
                new RightBorder { Val = BorderValues.Nil },
                new InsideHorizontalBorder { Val = BorderValues.Nil },
                new InsideVerticalBorder { Val = BorderValues.Nil })));
        tbl.AppendChild(new TableGrid(
            new GridColumn { Width = "3133" },
            new GridColumn { Width = "6267" }));

        var row = new TableRow();

        // LEFT cell: OrgLine1 + OrgLine2 + horizontal rule
        var leftCell = new TableCell();
        leftCell.AppendChild(new TableCellProperties(
            new TableCellWidth { Width = "3133", Type = TableWidthUnitValues.Dxa }));

        bool hasL1 = !string.IsNullOrWhiteSpace(m.OrgLine1);
        bool hasL2 = !string.IsNullOrWhiteSpace(m.OrgLine2);

        if (hasL1)
        {
            // Dòng 1 in thường, 13pt
            leftCell.AppendChild(MakeParagraph(m.OrgLine1, bold: false, align: JustificationValues.Center));
        }
        else
        {
            leftCell.AppendChild(MakeParagraph(new string('.', 28), bold: false, align: JustificationValues.Center));
        }

        if (hasL2)
        {
            // Dòng 2 IN HOA ĐẬM, 13pt
            var upper = m.OrgLine2.ToUpper(CultureInfo.CurrentCulture);
            leftCell.AppendChild(MakeParagraph(upper, bold: true, align: JustificationValues.Center));
        }
        else
        {
            leftCell.AppendChild(MakeParagraph(new string('.', 22), bold: false, align: JustificationValues.Center));
        }

        // Gạch ngang ngắn dưới đơn vị (như mẫu Công an VN)
        leftCell.AppendChild(MakeHorizontalRuleParagraph(widthChars: 12));

        row.AppendChild(leftCell);

        // RIGHT cell: CỘNG HÒA + Độc lập (gạch chân tích hợp vào chữ, không có vạch riêng)
        var rightCell = new TableCell();
        rightCell.AppendChild(new TableCellProperties(
            new TableCellWidth { Width = "6267", Type = TableWidthUnitValues.Dxa }));
        rightCell.AppendChild(MakeParagraph(
            "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM", bold: true, align: JustificationValues.Center));
        // Độc lập có gạch chân (underline trên chữ) như Mau 1.pdf — bỏ HorizontalRule riêng
        var mottoPara = new Paragraph();
        mottoPara.AppendChild(MakePPrWith(JustificationValues.Center));
        var mottoRun = new Run();
        mottoRun.AppendChild(MakeRunProps(bold: true, underline: true));
        mottoRun.AppendChild(new Text("Độc lập – Tự do – Hạnh phúc"));
        mottoPara.AppendChild(mottoRun);
        rightCell.AppendChild(mottoPara);

        // Dòng "<địa danh>, ngày ... tháng ... năm ..." — italic, căn giữa,
        // đặt NGAY DƯỚI motto trong cùng ô phải của bảng header. Nằm trong
        // ô phải (rộng ~11cm) nên không bị wrap như khi đặt riêng ra ngoài
        // bảng với indent-left trick cũ.
        rightCell.AppendChild(MakeHeaderDateParagraph(data));
        row.AppendChild(rightCell);

        tbl.AppendChild(row);
        body.AppendChild(tbl);
    }

    // ============ Date line (nằm trong ô phải, dưới motto) ============
    private static Paragraph MakeHeaderDateParagraph(ReportData data)
    {
        var m = data.Metadata;
        var gen = data.GeneratedAt.LocalDateTime;
        // Địa danh mặc định dùng 14 dấu chấm để vừa trong ô phải (~11cm)
        // khi render Times New Roman 13pt italic — không bị xuống dòng.
        string place = !string.IsNullOrWhiteSpace(m.Place) ? m.Place : new string('.', 14);
        string day = m.AutoDate ? gen.Day.ToString("D2", CultureInfo.InvariantCulture) : "…..";
        string month = m.AutoDate ? gen.Month.ToString("D2", CultureInfo.InvariantCulture) : "…..";
        string year = m.AutoDate ? gen.Year.ToString(CultureInfo.InvariantCulture) : "……";

        var p = new Paragraph();
        p.AppendChild(MakePPrWith(JustificationValues.Center));
        var run = new Run();
        run.AppendChild(MakeRunProps(bold: false, italic: true));
        run.AppendChild(new Text($"{place}, ngày {day} tháng {month} năm {year}")
            { Space = SpaceProcessingModeValues.Preserve });
        p.AppendChild(run);
        return p;
    }

    // ============ Title ============
    private static void WriteTitle(Body body)
    {
        body.AppendChild(MakeParagraph(string.Empty, bold: false)); // spacer
        body.AppendChild(MakeParagraph("BIÊN BẢN GHI NHẬN",
            bold: true, align: JustificationValues.Center, fontSize: FsTitle));
        // Subtitle in đậm KHÔNG gạch chân (user yêu cầu bỏ underline — khi in
        // nét underline chạm chấm của chữ "ỉ/ị" phía dưới gây rối mắt).
        var p = new Paragraph();
        p.AppendChild(MakePPrWith(JustificationValues.Center));
        var run = new Run();
        run.AppendChild(MakeRunProps(bold: true, underline: false));
        run.AppendChild(new Text("Kết quả kiểm tra việc đảm bảo an ninh mạng, an toàn thông tin"));
        p.AppendChild(run);
        body.AppendChild(p);
        body.AppendChild(MakeParagraph(string.Empty, bold: false));
    }

    // ============ Căn cứ / Thực hiện ============
    private static void WriteLegalBasis(Body body, ReportData data)
    {
        var m = data.Metadata;
        if (!string.IsNullOrWhiteSpace(m.LegalBasis))
        {
            foreach (var line in SplitLines(m.LegalBasis))
            {
                var p = new Paragraph();
                p.AppendChild(MakePPrWith(JustificationValues.Both,
                    firstLineIndentTwips: 567, lineSpacing1_5: true));
                p.AppendChild(MakeRunText(line));
                body.AppendChild(p);
            }
        }
        else
        {
            // Căn cứ kiểm tra: + 3 dòng chấm
            var p = new Paragraph();
            p.AppendChild(MakePPrWith(JustificationValues.Both));
            p.AppendChild(MakeRunText("Căn cứ kiểm tra:", bold: true));
            body.AppendChild(p);

            for (int i = 0; i < 3; i++)
            {
                body.AppendChild(MakeDottedLineParagraph());
            }
        }
    }

    // ============ Hồi ... tại: ============
    private static void WriteTimeLocation(Body body, ReportData data)
    {
        var m = data.Metadata;
        var gen = data.GeneratedAt.LocalDateTime;

        string hour = m.AutoDate ? gen.Hour.ToString("D2", CultureInfo.InvariantCulture) : "…..";
        string minute = m.AutoDate ? gen.Minute.ToString("D2", CultureInfo.InvariantCulture) : "…..";
        string day = m.AutoDate ? gen.Day.ToString("D2", CultureInfo.InvariantCulture) : "…..";
        string month = m.AutoDate ? gen.Month.ToString("D2", CultureInfo.InvariantCulture) : "…..";
        string year = m.AutoDate ? gen.Year.ToString(CultureInfo.InvariantCulture) : "……";

        string location = !string.IsNullOrWhiteSpace(m.InspectionLocation)
            ? m.InspectionLocation.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim()
            : "……………………………………………………………………";

        var p = new Paragraph();
        p.AppendChild(MakePPrWith(JustificationValues.Both,
            firstLineIndentTwips: 567, lineSpacing1_5: true));
        p.AppendChild(MakeRunText(
            $"Hồi {hour} giờ {minute} phút ngày {day} tháng {month} năm {year}, tại {location}, Tổ kiểm tra thực hiện kiểm tra với nội dung như sau:"));
        body.AppendChild(p);
    }

    // ============ I. Thành phần ============
    private static void WriteParticipants(Body body, ReportData data)
    {
        var m = data.Metadata;
        body.AppendChild(MakeParagraph("I. THÀNH PHẦN", bold: true));

        body.AppendChild(MakeParagraph("1. Tổ kiểm tra", bold: true));
        if (!string.IsNullOrWhiteSpace(m.InspectionTeam))
        {
            foreach (var line in SplitLines(m.InspectionTeam))
            {
                body.AppendChild(MakeListParagraph(line));
            }
        }
        else
        {
            for (int i = 0; i < 3; i++)
            {
                body.AppendChild(MakeDottedLineParagraph());
            }
        }

        body.AppendChild(MakeParagraph("2. Đơn vị có phương tiện, thiết bị được kiểm tra:", bold: true));
        if (!string.IsNullOrWhiteSpace(m.AuditedUnitDetail))
        {
            foreach (var line in SplitLines(m.AuditedUnitDetail))
            {
                body.AppendChild(MakeListParagraph(line));
            }
        }
        else
        {
            for (int i = 0; i < 3; i++)
            {
                body.AppendChild(MakeDottedLineParagraph());
            }
        }
    }

    // ============ II. Kết quả kiểm tra ============
    private static void WriteResults(Body body, ReportData data)
    {
        body.AppendChild(MakeParagraph("II. KẾT QUẢ KIỂM TRA", bold: true));

        // 1. Thông tin thiết bị
        body.AppendChild(MakeParagraph("1. Thông tin thiết bị kiểm tra", bold: true));
        var biosLine = data.Device.BiosVendor;
        if (!string.IsNullOrWhiteSpace(data.Device.BiosVersion))
        {
            biosLine += " — phiên bản " + data.Device.BiosVersion;
        }
        if (data.Device.BiosReleaseDate.HasValue)
        {
            biosLine += " (phát hành " + data.Device.BiosReleaseDate.Value.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture) + ")";
        }
        var tpmText = (data.Device.TpmPresent
                ? "TPM có (" + (data.Device.TpmSpecVersion ?? "?") + ")"
                : "TPM không")
            + " — Secure Boot " + (data.Device.SecureBootEnabled ? "bật" : "tắt");
        var diskText = data.Device.Disks.Count == 0
            ? "(không liệt kê được)"
            : string.Join("\n", data.Device.Disks.Select(d =>
                $"{d.Model} — {d.InterfaceType} — {d.Size}"
                + (string.IsNullOrEmpty(d.SerialNumber) ? string.Empty : $" — SN {d.SerialNumber}")));
        var kvRows = new[]
        {
            ("Tên máy tính", data.Device.ComputerName),
            ("CPU", data.Device.Cpu),
            ("BIOS", biosLine),
            ("Serial Number BIOS", data.Device.BiosSerial),
            ("RAM", data.Device.TotalRam),
            ("Hệ điều hành", data.Device.OperatingSystem),
            ("TPM / Secure Boot", tpmText),
            ("Ổ đĩa vật lý", diskText),
            ("Địa chỉ MAC / IP", data.Device.NetworkAddresses.Count == 0
                ? "(không phát hiện giao tiếp mạng đang hoạt động)"
                : string.Join("\n", data.Device.NetworkAddresses.Select(n =>
                    $"{n.InterfaceName} — MAC {n.MacAddress} — IPv4 {n.IPv4}"
                    + (string.IsNullOrEmpty(n.IPv6) ? string.Empty : $" — IPv6 {n.IPv6}"))))
        };
        body.AppendChild(BuildKeyValueTable(kvRows));

        // 1b. License (Windows / Office)
        if (data.License is not null)
        {
            body.AppendChild(MakeParagraph("1b. Trạng thái bản quyền (Windows / Office)", bold: true));
            var licRows = new List<(string, string)>
            {
                ("Windows — " + data.License.Windows.Product, FormatLicenseEntry(data.License.Windows))
            };
            if (data.License.Office.Count == 0)
            {
                licRows.Add(("Office", "(không cài Microsoft Office)"));
            }
            else
            {
                foreach (var o in data.License.Office)
                {
                    licRows.Add(("Office — " + o.Product, FormatLicenseEntry(o)));
                }
            }
            if (data.License.OfficeKmsPicoSuspected)
            {
                licRows.Add(("Cảnh báo crack / KMSpico",
                    "Phát hiện dấu hiệu công cụ kích hoạt trái phép:\n - "
                    + string.Join("\n - ", data.License.OfficeKmsPicoEvidence)));
            }
            body.AppendChild(BuildKeyValueTable(licRows.ToArray()));
        }

        // 1c. Patch summary
        if (data.Patch is not null)
        {
            body.AppendChild(MakeParagraph("1c. Tổng hợp bản vá & CSDL CVE", bold: true));
            var patchRows = new (string, string)[]
            {
                ("Số bản vá KB đã cài", data.Patch.InstalledKbCount.ToString(CultureInfo.InvariantCulture)),
                ("Quy tắc CVE quan trọng còn thiếu",
                    data.Patch.MissingCriticalRuleCount == 0
                        ? "0 — máy đã được vá đầy đủ theo bộ quy tắc nội bộ."
                        : data.Patch.MissingCriticalRuleCount + " quy tắc chưa khớp KB nào (xem chi tiết phía dưới)."),
                ("CSDL CVE đồng bộ lần cuối",
                    data.Patch.CveDbLastSync.HasValue
                        ? data.Patch.CveDbLastSync.Value.LocalDateTime.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture)
                            + (data.Patch.CveDbStale ? " (đã quá hạn 30 ngày)" : string.Empty)
                        : "chưa từng đồng bộ")
            };
            body.AppendChild(BuildKeyValueTable(patchRows));
        }

        // 1d. Scan scope
        if (data.Scope is not null)
        {
            body.AppendChild(MakeParagraph("1d. Phạm vi quét", bold: true));
            var scopeRows = new List<(string, string)>();
            if (data.Scope.AutorunTotal.HasValue)
            {
                scopeRows.Add(("Mục khởi động (Run/RunOnce)",
                    $"{data.Scope.AutorunSuspicious ?? 0} đáng ngờ / tổng {data.Scope.AutorunTotal.Value}"));
            }
            if (data.Scope.ServiceSuspicious.HasValue)
            {
                scopeRows.Add(("Dịch vụ auto-start đáng ngờ",
                    data.Scope.ServiceSuspicious.Value.ToString(CultureInfo.InvariantCulture)));
            }
            if (data.Scope.ScheduledTaskSuspicious.HasValue)
            {
                scopeRows.Add(("Scheduled task đáng ngờ",
                    data.Scope.ScheduledTaskSuspicious.Value.ToString(CultureInfo.InvariantCulture)));
            }
            if (data.Scope.WmiPersistenceCount.HasValue)
            {
                scopeRows.Add(("WMI permanent event subscription",
                    data.Scope.WmiPersistenceCount.Value + " (Windows sạch thường 0–2)"));
            }
            if (data.Scope.ForensicsRun)
            {
                scopeRows.Add(("Phiên Log Forensics",
                    $"Mã: {data.Scope.ForensicsSessionId}\n"
                    + $"Đã phân tích {data.Scope.ForensicsTotalRecords} bản ghi từ {data.Scope.ForensicsTotalFiles} tệp; "
                    + $"lưu {data.Scope.ForensicsManifestCount} tệp evidence tại {data.Scope.ForensicsEvidenceRoot}."));
            }
            if (scopeRows.Count > 0)
            {
                body.AppendChild(BuildKeyValueTable(scopeRows.ToArray()));
            }
        }

        if (data.TotalFindings > 0)
        {
            body.AppendChild(MakeParagraph("1e. Hướng dẫn xử lý nhanh cho người vận hành", bold: true));
            body.AppendChild(BuildKeyValueTable(new[]
            {
                ("Nhóm xử lý", CountTriageText(data.AllFindings, t => t.ActionGroup)),
                ("Tình huống", CountTriageText(data.AllFindings, t => t.Scenario)),
                ("Cách đọc",
                    "Cần xử lý ngay: lưu bằng chứng, cô lập/chặn/khắc phục.\n"
                    + "Cần xử lý: khắc phục theo chính sách hoặc kế hoạch gần nhất.\n"
                    + "Cần xem lại: đối chiếu baseline, người dùng và log trước khi kết luận.\n"
                    + "Có thể bỏ qua / Thông tin: giữ để tham khảo, không coi là IOC độc hại.")
            }));
        }

        int idx = 2;
        if (data.TotalFindings == 0 && data.ByModule.Count == 0)
        {
            var p = new Paragraph();
            p.AppendChild(MakePPrWith(JustificationValues.Both,
                firstLineIndentTwips: 567, lineSpacing1_5: true));
            var r = new Run();
            r.AppendChild(MakeRunProps(italic: true));
            r.AppendChild(new Text("Không phát hiện vấn đề nào. Hệ thống đang ở trạng thái tốt."));
            p.AppendChild(r);
            body.AppendChild(p);
        }
        else
        {
            foreach (var (moduleId, findings) in data.ByModule)
            {
                var viName = ModuleNameTranslator.Translate(moduleId);
                body.AppendChild(MakeParagraph(
                    $"{idx}. {viName} — {findings.Count} phát hiện", bold: true));

                if (findings.Count == 0)
                {
                    body.AppendChild(MakeParagraph(
                        "Không có phát hiện nào ở module này.", bold: false, italic: true));
                }
                else
                {
                    body.AppendChild(BuildFindingsTable(findings));
                }
                idx++;
            }
        }

        if (data.AppliedActions.Count > 0)
        {
            body.AppendChild(MakeParagraph(
                $"{idx}. Nội dung đã xử lý khắc phục", bold: true));
            body.AppendChild(BuildAppliedTable(data.AppliedActions));
            idx++;
        }

    }

    // ============ Closing ============
    private static void WriteClosing(Body body)
    {
        body.AppendChild(MakeParagraph(string.Empty, bold: false));
        var p = new Paragraph();
        p.AppendChild(MakePPrWith(JustificationValues.Both,
            firstLineIndentTwips: 567, lineSpacing1_5: true));
        p.AppendChild(MakeRunText(
            "Biên bản kết thúc hồi ….. giờ ….. phút cùng ngày; đã thông qua các bên cùng nhất trí và ký tên dưới đây./."));
        body.AppendChild(p);
    }

    // ============ 2×2 signature grid ============
    private static void WriteSignatures(Body body, ReportData data)
    {
        var m = data.Metadata;
        body.AppendChild(MakeParagraph(string.Empty, bold: false));

        var tbl = new Table();
        tbl.AppendChild(new TableProperties(
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct },
            new TableLayout { Type = TableLayoutValues.Fixed },
            new TableBorders(
                new TopBorder { Val = BorderValues.Nil },
                new BottomBorder { Val = BorderValues.Nil },
                new LeftBorder { Val = BorderValues.Nil },
                new RightBorder { Val = BorderValues.Nil },
                new InsideHorizontalBorder { Val = BorderValues.Nil },
                new InsideVerticalBorder { Val = BorderValues.Nil })));
        tbl.AppendChild(new TableGrid(
            new GridColumn { Width = "4700" },
            new GridColumn { Width = "4700" }));

        tbl.AppendChild(MakeSignatureRow(
            "ĐẠI DIỆN", "ĐƠN VỊ ĐƯỢC KIỂM TRA", m.AuditedUnit,
            "TỔ TRƯỞNG", "TỔ KIỂM TRA", m.TeamLeader));

        // Row cách giữa 2 cặp chữ ký (để chỗ ký thoáng hơn)
        tbl.AppendChild(MakeSpacerRow());

        tbl.AppendChild(MakeSignatureRow(
            "CÁN BỘ THAM GIA", string.Empty, m.TeamMember,
            "CÁN BỘ LẬP BIÊN BẢN", string.Empty, m.Recorder));

        body.AppendChild(tbl);
    }

    private static TableRow MakeSignatureRow(
        string roleLeft1, string roleLeft2, string signerLeft,
        string roleRight1, string roleRight2, string signerRight)
    {
        var row = new TableRow();
        row.AppendChild(MakeSignatureCell(roleLeft1, roleLeft2, signerLeft));
        row.AppendChild(MakeSignatureCell(roleRight1, roleRight2, signerRight));
        return row;
    }

    private static TableCell MakeSignatureCell(string role1, string role2, string signer)
    {
        var cell = new TableCell();
        cell.AppendChild(new TableCellProperties(
            new TableCellWidth { Width = "4700", Type = TableWidthUnitValues.Dxa }));
        cell.AppendChild(MakeParagraph(role1, bold: true, align: JustificationValues.Center));
        if (!string.IsNullOrEmpty(role2))
        {
            cell.AppendChild(MakeParagraph(role2, bold: true, align: JustificationValues.Center));
        }
        // Khoảng trống để ký (khoảng 3 paragraph rỗng)
        for (int i = 0; i < 4; i++)
        {
            cell.AppendChild(MakeParagraph(string.Empty, bold: false, align: JustificationValues.Center));
        }
        if (!string.IsNullOrWhiteSpace(signer))
        {
            cell.AppendChild(MakeParagraph(signer, bold: true, align: JustificationValues.Center));
        }
        return cell;
    }

    private static TableRow MakeSpacerRow()
    {
        var row = new TableRow();
        for (int i = 0; i < 2; i++)
        {
            var cell = new TableCell();
            cell.AppendChild(new TableCellProperties(
                new TableCellWidth { Width = "4700", Type = TableWidthUnitValues.Dxa }));
            cell.AppendChild(MakeParagraph(string.Empty, bold: false));
            row.AppendChild(cell);
        }
        return row;
    }

    // ============ Helpers: paragraph / run builders ============
    private static Paragraph MakeParagraph(
        string text,
        bool bold = false,
        bool italic = false,
        JustificationValues? align = null,
        string? fontSize = null)
    {
        var p = new Paragraph();
        p.AppendChild(MakePPrWith(align ?? JustificationValues.Both));
        if (text.Length == 0)
        {
            return p;
        }
        var run = new Run();
        run.AppendChild(MakeRunProps(bold: bold, italic: italic, fontSize: fontSize));
        run.AppendChild(new Text(text) { Space = SpaceProcessingModeValues.Preserve });
        p.AppendChild(run);
        return p;
    }

    private static Paragraph MakeListParagraph(string text)
    {
        var p = new Paragraph();
        p.AppendChild(MakePPrWith(JustificationValues.Both, firstLineIndentTwips: 567, lineSpacing1_5: true));
        p.AppendChild(MakeRunText(text));
        return p;
    }

    private static Paragraph MakeDottedLineParagraph()
    {
        // Một dòng chấm dài chiếm gần hết chiều ngang
        return MakeParagraph(new string('.', 120), bold: false, align: JustificationValues.Left);
    }

    private static Paragraph MakeHorizontalRuleParagraph(int widthChars)
    {
        // Gạch ngang bằng ký tự em-dash (—) hoặc underscore; dùng "———" dài widthChars
        return MakeParagraph(new string('—', widthChars), bold: false, align: JustificationValues.Center);
    }

    private static ParagraphProperties MakePPrWith(
        JustificationValues align,
        int indentLeftChars = 0,
        int firstLineIndentTwips = 0,
        bool lineSpacing1_5 = false)
    {
        var pPr = new ParagraphProperties(new Justification { Val = align });
        if (indentLeftChars > 0 || firstLineIndentTwips > 0)
        {
            var ind = new Indentation();
            if (firstLineIndentTwips > 0)
            {
                ind.FirstLine = firstLineIndentTwips.ToString(CultureInfo.InvariantCulture);
            }
            pPr.AppendChild(ind);
        }
        if (lineSpacing1_5)
        {
            pPr.AppendChild(new SpacingBetweenLines { Line = "360", LineRule = LineSpacingRuleValues.Auto });
        }
        // Font ép cứng ở paragraph level
        pPr.AppendChild(new ParagraphMarkRunProperties(
            new RunFonts { Ascii = FontName, HighAnsi = FontName, ComplexScript = FontName, EastAsia = FontName },
            new FontSize { Val = FsNormal },
            new FontSizeComplexScript { Val = FsNormal }));
        return pPr;
    }

    private static RunProperties MakeRunProps(
        bool bold = false,
        bool italic = false,
        bool underline = false,
        string? fontSize = null)
    {
        var props = new RunProperties(
            new RunFonts { Ascii = FontName, HighAnsi = FontName, ComplexScript = FontName, EastAsia = FontName },
            new FontSize { Val = fontSize ?? FsNormal },
            new FontSizeComplexScript { Val = fontSize ?? FsNormal });
        if (bold)
        {
            props.AppendChild(new Bold());
            props.AppendChild(new BoldComplexScript());
        }
        if (italic)
        {
            props.AppendChild(new Italic());
            props.AppendChild(new ItalicComplexScript());
        }
        if (underline)
        {
            props.AppendChild(new Underline { Val = UnderlineValues.Single });
        }
        return props;
    }

    private static Run MakeRunText(string text, bool bold = false, bool italic = false)
    {
        var r = new Run();
        r.AppendChild(MakeRunProps(bold, italic));
        r.AppendChild(new Text(text) { Space = SpaceProcessingModeValues.Preserve });
        return r;
    }

    // ============ Tables ============
    private static Table MakeBorderedTable()
    {
        var tbl = new Table();
        tbl.AppendChild(new TableProperties(
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct },
            new TableLayout { Type = TableLayoutValues.Autofit },
            new TableBorders(
                new TopBorder { Val = BorderValues.Single, Size = 6, Color = "444444" },
                new BottomBorder { Val = BorderValues.Single, Size = 6, Color = "444444" },
                new LeftBorder { Val = BorderValues.Single, Size = 6, Color = "444444" },
                new RightBorder { Val = BorderValues.Single, Size = 6, Color = "444444" },
                new InsideHorizontalBorder { Val = BorderValues.Single, Size = 4, Color = "888888" },
                new InsideVerticalBorder { Val = BorderValues.Single, Size = 4, Color = "888888" })));
        return tbl;
    }

    private static Table BuildKeyValueTable((string k, string v)[] rows)
    {
        var tbl = MakeBorderedTable();
        tbl.AppendChild(new TableGrid(
            new GridColumn { Width = "2800" },
            new GridColumn { Width = "6600" }));
        foreach (var (k, v) in rows)
        {
            var row = new TableRow();
            row.AppendChild(MakeShadedCell(k, bold: true, shade: "F2F2F2", width: "2800"));
            row.AppendChild(MakeTextCell(v, width: "6600"));
            tbl.AppendChild(row);
        }
        return tbl;
    }

    private static Table BuildFindingsTable(IEnumerable<SecAudit.Core.Models.Finding> findings)
    {
        // 3 cột: Mức / Mã / Tiêu đề+Bằng chứng (gộp). Diễn giải và quy trình xử lý
        // nằm ngay trong từng bằng chứng để người đọc không phải đối chiếu section cuối.
        var tbl = MakeBorderedTable();
        tbl.AppendChild(new TableGrid(
            new GridColumn { Width = "900" },
            new GridColumn { Width = "1400" },
            new GridColumn { Width = "7100" }));
        var head = new TableRow();
        head.AppendChild(MakeShadedCell("Mức", bold: true, shade: "E9E9E9", width: "900", center: true));
        head.AppendChild(MakeShadedCell("Mã", bold: true, shade: "E9E9E9", width: "1400", center: true));
        head.AppendChild(MakeShadedCell("Tiêu đề & bằng chứng", bold: true, shade: "E9E9E9",
            width: "7100", center: true));
        tbl.AppendChild(head);

        foreach (var f in findings.OrderByDescending(x => (int)x.Severity))
        {
            var row = new TableRow();
            row.AppendChild(MakeTextCell(f.Severity.ToString(), width: "900", bold: true, center: true));
            row.AppendChild(MakeTextCell(f.Id, width: "1400"));
            row.AppendChild(MakeTitleAndEvidenceCell(f, width: "7100"));
            tbl.AppendChild(row);
        }
        return tbl;
    }

    /// <summary>
    /// Build a single Word table cell that stacks a bold title paragraph on top, and the
    /// numbered evidence (each line a separate paragraph so Word respects the line breaks)
    /// underneath. Empty evidence yields a title-only cell.
    /// </summary>
    private static TableCell MakeTitleAndEvidenceCell(SecAudit.Core.Models.Finding finding, string width)
    {
        var cell = new TableCell();
        cell.AppendChild(new TableCellProperties(
            new TableCellWidth { Width = width, Type = TableWidthUnitValues.Dxa }));

        var triage = FindingTriageInterpreter.Interpret(finding);
        cell.AppendChild(MakeParagraph(finding.Title, bold: true, align: JustificationValues.Both));
        cell.AppendChild(MakeParagraph(
            $"Xử lý: {triage.ActionGroup} | Tin cậy: {triage.Confidence} | Tình huống: {triage.Scenario}",
            bold: false,
            align: JustificationValues.Left));
        cell.AppendChild(MakeParagraph("Diễn giải: " + triage.Explanation, bold: false,
            align: JustificationValues.Both));
        if (triage.Steps.Count > 0)
        {
            cell.AppendChild(MakeParagraph("Quy trình xử lý:", bold: true,
                align: JustificationValues.Left));
            for (int i = 0; i < triage.Steps.Count; i++)
            {
                cell.AppendChild(MakeParagraph($"{i + 1}. {triage.Steps[i]}", bold: false,
                    align: JustificationValues.Left));
            }
        }

        var ev = EvidenceFormatter.NumberBullets(finding.Evidence ?? string.Empty);
        if (!string.IsNullOrEmpty(ev))
        {
            cell.AppendChild(MakeParagraph("Bằng chứng:", bold: true,
                align: JustificationValues.Left));
            foreach (var line in ev.Split('\n'))
            {
                cell.AppendChild(MakeParagraph(line.Trim('\r'), bold: false,
                    align: JustificationValues.Left));
            }
        }
        return cell;
    }

    private static Table BuildAppliedTable(IEnumerable<SecAudit.Reporting.Models.AppliedAction> actions)
    {
        var tbl = MakeBorderedTable();
        tbl.AppendChild(new TableGrid(
            new GridColumn { Width = "1400" },
            new GridColumn { Width = "2200" },
            new GridColumn { Width = "1200" },
            new GridColumn { Width = "2500" },
            new GridColumn { Width = "900" },
            new GridColumn { Width = "1200" }));
        var head = new TableRow();
        head.AppendChild(MakeShadedCell("Mã lỗi", true, "E9E9E9", "1400", center: true));
        head.AppendChild(MakeShadedCell("Hành động", true, "E9E9E9", "2200", center: true));
        head.AppendChild(MakeShadedCell("Kết quả", true, "E9E9E9", "1200", center: true));
        head.AppendChild(MakeShadedCell("Chi tiết", true, "E9E9E9", "2500", center: true));
        head.AppendChild(MakeShadedCell("Reboot?", true, "E9E9E9", "900", center: true));
        head.AppendChild(MakeShadedCell("Thời điểm", true, "E9E9E9", "1200", center: true));
        tbl.AppendChild(head);

        foreach (var a in actions)
        {
            var row = new TableRow();
            row.AppendChild(MakeTextCell(a.FindingId, width: "1400"));
            row.AppendChild(MakeTextCell(a.ActionTitle, width: "2200"));
            row.AppendChild(MakeTextCell(a.Succeeded ? "Thành công" : "Thất bại",
                width: "1200", bold: true, center: true));
            row.AppendChild(MakeTextCell(a.Message, width: "2500"));
            row.AppendChild(MakeTextCell(a.RebootRequired ? "Có" : "Không", width: "900", center: true));
            row.AppendChild(MakeTextCell(
                a.AppliedAt.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                width: "1200"));
            tbl.AppendChild(row);
        }
        return tbl;
    }

    private static TableCell MakeShadedCell(string text, bool bold, string shade, string width, bool center = false)
    {
        var cell = new TableCell();
        cell.AppendChild(new TableCellProperties(
            new TableCellWidth { Width = width, Type = TableWidthUnitValues.Dxa },
            new Shading { Val = ShadingPatternValues.Clear, Fill = shade, Color = "auto" }));
        cell.AppendChild(MakeParagraph(text, bold: bold,
            align: center ? JustificationValues.Center : JustificationValues.Left));
        return cell;
    }

    private static TableCell MakeTextCell(string text, string width, bool bold = false, bool center = false)
    {
        var cell = new TableCell();
        cell.AppendChild(new TableCellProperties(
            new TableCellWidth { Width = width, Type = TableWidthUnitValues.Dxa }));
        // Tách text theo \n thành nhiều paragraph trong cùng cell
        var lines = string.IsNullOrEmpty(text) ? new[] { string.Empty } : text.Split('\n');
        foreach (var line in lines)
        {
            cell.AppendChild(MakeParagraph(line.Trim('\r'), bold: bold,
                align: center ? JustificationValues.Center : JustificationValues.Both));
        }
        return cell;
    }

    // ============ License formatting ============
    /// <summary>
    /// Multiline summary for a single SLP product entry (used in 1b. License table).
    /// Mirrors PdfReportWriter.FormatLicenseEntry so all three writers produce identical
    /// per-entry text (only the surrounding visual chrome differs).
    /// </summary>
    private static string FormatLicenseEntry(LicenseEntry e)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("Tình trạng: ").Append(e.StatusText)
          .Append(" (mã ").Append(e.StatusCode.ToString(CultureInfo.InvariantCulture)).Append(')');
        if (!string.IsNullOrWhiteSpace(e.Description))
        {
            sb.Append('\n').Append("Mô tả: ").Append(e.Description);
        }
        if (!string.IsNullOrWhiteSpace(e.KmsServer))
        {
            sb.Append('\n').Append("KMS server: ").Append(e.KmsServer);
        }
        if (!string.IsNullOrWhiteSpace(e.PartialProductKey))
        {
            sb.Append('\n').Append("5 ký tự cuối product key: ").Append(e.PartialProductKey);
        }
        sb.Append('\n').Append("Genuine: ").Append(e.IsGenuine ? "có" : "không");
        return sb.ToString();
    }

    private static string CountTriageText(
        IEnumerable<SecAudit.Core.Models.Finding> findings,
        Func<SecAudit.Core.Models.FindingTriage, string> selector)
        => string.Join(
            "\n",
            findings
                .Select(f => selector(FindingTriageInterpreter.Interpret(f)))
                .GroupBy(value => value, StringComparer.Ordinal)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => $"{g.Key}: {g.Count()} phát hiện"));

    // ============ Common ============
    private static string[] SplitLines(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }
        var normalized = value.Replace("\r\n", "\n").Replace('\r', '\n');
        return normalized.Split('\n', StringSplitOptions.RemoveEmptyEntries);
    }
}
