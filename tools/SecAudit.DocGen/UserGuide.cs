using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace SecAudit.DocGen;

/// <summary>
/// Toàn bộ nội dung "Hướng dẫn sử dụng SecAudit" — tiếng Việt, có cấu trúc rõ
/// ràng, in trên A4 (font serif tiếng Việt Unicode). QuestPDF dùng font mặc
/// định của hệ thống — trên Windows là Segoe UI / Arial, hỗ trợ đầy đủ diacritic.
/// </summary>
internal static class UserGuide
{
    // ----- Màu chủ đạo (navy + accent vàng) -----
    private const string Primary   = "#0B3D91"; // navy sâu
    private const string Accent    = "#D97706"; // cam amber
    private const string Muted     = "#4B5563";
    private const string LightGray = "#E5E7EB";
    private const string DarkGray  = "#1F2937";
    private const string SoftBg    = "#F3F4F6";
    private const string GreenOk   = "#047857";
    private const string RedBad    = "#B91C1C";

    public static void Compose(IDocumentContainer doc)
    {
        doc.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(1.8f, Unit.Centimetre);
            page.PageColor(Colors.White);
            page.DefaultTextStyle(t => t.FontSize(10.5f).FontColor(DarkGray).LineHeight(1.35f));

            page.Header().Element(Header);
            page.Content().Element(Body);
            page.Footer().Element(Footer);
        });
    }

    // =========================================================================
    // HEADER / FOOTER
    // =========================================================================
    private static void Header(IContainer c) => c.ShowOnce().Column(col =>
    {
        col.Item().Row(r =>
        {
            r.RelativeItem().Column(inner =>
            {
                inner.Item().Text("SecAudit")
                    .FontSize(22).Bold().FontColor(Primary);
                inner.Item().Text("Công cụ kiểm tra An ninh mạng & ATTT cho Windows 10/11")
                    .FontSize(10).FontColor(Muted);
            });
            r.ConstantItem(140).AlignRight().Column(inner =>
            {
                inner.Item().Text($"Phiên bản 0.1.0").FontSize(9).FontColor(Muted);
                inner.Item().Text($"Cập nhật: {DateTime.Now:dd/MM/yyyy}").FontSize(9).FontColor(Muted);
            });
        });
        col.Item().PaddingTop(6).LineHorizontal(1).LineColor(Primary);
    });

    private static void Footer(IContainer c) => c.AlignCenter().Text(t =>
    {
        t.DefaultTextStyle(s => s.FontSize(8.5f).FontColor(Muted));
        t.Span("SecAudit • Hướng dẫn sử dụng • ");
        t.CurrentPageNumber();
        t.Span(" / ");
        t.TotalPages();
    });

    // =========================================================================
    // BODY — toàn bộ nội dung
    // =========================================================================
    private static void Body(IContainer c) => c.PaddingVertical(10).Column(col =>
    {
        col.Spacing(10);

        Cover(col);
        col.Item().PageBreak();

        Toc(col);
        col.Item().PageBreak();

        Section1_Overview(col);
        col.Item().PageBreak();

        Section2_Architecture(col);
        col.Item().PageBreak();

        Section3_Modules(col);
        col.Item().PageBreak();

        Section4_GuiUsage(col);
        col.Item().PageBreak();

        Section5_LogForensicsWorkflow(col);
        col.Item().PageBreak();

        Section6_Cli(col);
        col.Item().PageBreak();

        Section7_Reports(col);
        col.Item().PageBreak();

        Section8_Security(col);
        col.Item().PageBreak();

        Section9_Faq(col);
    });

    // =========================================================================
    // TRANG BÌA
    // =========================================================================
    private static void Cover(ColumnDescriptor col)
    {
        col.Item().PaddingTop(40).AlignCenter().Text("HƯỚNG DẪN SỬ DỤNG")
            .FontSize(14).FontColor(Accent).LetterSpacing(0.3f);

        col.Item().PaddingTop(8).AlignCenter().Text("SecAudit")
            .FontSize(48).Bold().FontColor(Primary);

        col.Item().PaddingTop(4).AlignCenter().Text("Ứng dụng kiểm tra An ninh mạng & ATTT")
            .FontSize(16).FontColor(DarkGray);

        col.Item().PaddingTop(2).AlignCenter().Text("cho máy trạm Windows 10 / 11")
            .FontSize(16).FontColor(DarkGray);

        col.Item().PaddingTop(40).AlignCenter().Container().Width(380).Background(SoftBg)
            .Padding(16).Column(inner =>
            {
                inner.Spacing(6);
                inner.Item().Text("TÓM TẮT SẢN PHẨM").FontSize(10).Bold().FontColor(Primary);
                inner.Item().Text(
                    "SecAudit là công cụ portable một tệp .exe duy nhất, chạy quyền Administrator, " +
                    "hoạt động offline-first. Ứng dụng gộp 6 nhóm nghiệp vụ: thu thập thông tin hệ " +
                    "thống, rà soát cấu hình theo CIS, tra cứu CVE, quét LAN, phát hiện công cụ " +
                    "điều khiển từ xa / keylogger, và đặc biệt là phân tích nhật ký (log forensics) " +
                    "với 18 rule phát hiện + 8 kill-chain MITRE ATT&CK và bộ lọc khoảng thời gian.")
                    .FontSize(10).FontColor(DarkGray);
            });

        col.Item().PaddingTop(60).AlignCenter().Column(inner =>
        {
            inner.Item().Text("Phát hành cho: Phòng An ninh mạng & Phòng chống tội phạm công nghệ cao")
                .FontSize(10.5f).Bold().FontColor(DarkGray);
            inner.Item().PaddingTop(2).Text("(Công an tỉnh Sơn La và các đơn vị SOC nội bộ doanh nghiệp)")
                .FontSize(10).FontColor(Muted);
        });

        col.Item().PaddingTop(80).AlignCenter().Text($"Tài liệu sinh tự động ngày {DateTime.Now:dd/MM/yyyy}")
            .FontSize(9).FontColor(Muted).Italic();
    }

    // =========================================================================
    // MỤC LỤC
    // =========================================================================
    private static void Toc(ColumnDescriptor col)
    {
        SectionTitle(col, "MỤC LỤC");

        (string n, string title)[] items = {
            ("1.", "Giới thiệu tổng quan"),
            ("2.", "Kiến trúc & yêu cầu môi trường"),
            ("3.", "Danh sách tính năng theo module"),
            ("3.1", "  System Info & License (Module 1)"),
            ("3.2", "  Hardening Audit — CIS checks (Module 2)"),
            ("3.3", "  Patch & CVE Audit (Module 3)"),
            ("3.4", "  LAN Scanner /24 (Module 4)"),
            ("3.5", "  Remote Access & Keylogger Detection (Module 5)"),
            ("3.6", "  Log Forensics — phân tích nhật ký (Module 6)"),
            ("4.", "Hướng dẫn sử dụng giao diện đồ hoạ"),
            ("5.", "Quy trình chuẩn: Log Forensics end-to-end"),
            ("6.", "Chế độ dòng lệnh (CLI) & kịch bản WinPE offline"),
            ("7.", "Báo cáo: HTML / PDF / DOCX / JSON"),
            ("8.", "Bảo mật, audit log & tuân thủ pháp luật"),
            ("9.", "Câu hỏi thường gặp & xử lý sự cố"),
        };

        foreach (var (n, title) in items)
        {
            col.Item().Row(r =>
            {
                r.ConstantItem(36).Text(n).FontColor(Primary).Bold();
                r.RelativeItem().Text(title).FontColor(DarkGray);
            });
        }
    }

    // =========================================================================
    // 1. GIỚI THIỆU
    // =========================================================================
    private static void Section1_Overview(ColumnDescriptor col)
    {
        SectionTitle(col, "1. GIỚI THIỆU TỔNG QUAN");

        Paragraph(col,
            "SecAudit được thiết kế dành riêng cho quản trị viên hệ thống và đội SOC nội bộ — " +
            "đặc biệt là các cơ quan phải đánh giá nhanh tình trạng an ninh của máy trạm Windows " +
            "trong thời gian ngắn, có thể ở hiện trường (ngắt mạng), hoặc trên ổ cứng đã tháo ra " +
            "thông qua USB boot WinPE.");

        Paragraph(col,
            "Khác với các SIEM/EDR thương mại vận hành đám mây, SecAudit tập trung vào yêu cầu " +
            "“offline-first” — toàn bộ quy tắc phát hiện, CSDL CVE, và template báo cáo được nhúng " +
            "sẵn trong tệp thực thi. Cơ quan sử dụng không cần kết nối Internet, không cần cài " +
            "runtime .NET bên ngoài, không phụ thuộc WebView2.");

        Subheading(col, "Mục tiêu chính");
        Bullets(col,
            "Tạo báo cáo kỹ thuật + biên bản pháp lý tiếng Việt trong dưới 15 phút cho một máy trạm.",
            "Phát hiện brute-force, logon lạ, ransomware, keylogger, data-destruction từ nhật ký thô.",
            "Chấp hành Luật An ninh mạng 2018 (Điều 8) và Bộ luật Hình sự 2015 Điều 289 — mọi " +
                "thao tác nhạy cảm đều được ghi vào sổ audit ký số.",
            "Hỗ trợ song ngữ Việt – Anh (vi-VN mặc định); hoạt động cả khi kiểm thử từ WinPE USB.");

        Subheading(col, "Đối tượng người dùng");
        Bullets(col,
            "Quản trị viên / SOC analyst trong doanh nghiệp Việt Nam.",
            "Điều tra viên kỹ thuật số (cán bộ Phòng ANM & PCTP CNC).",
            "Đơn vị thanh tra công nghệ thông tin, kiểm toán nội bộ.");
    }

    // =========================================================================
    // 2. KIẾN TRÚC
    // =========================================================================
    private static void Section2_Architecture(ColumnDescriptor col)
    {
        SectionTitle(col, "2. KIẾN TRÚC & YÊU CẦU MÔI TRƯỜNG");

        Subheading(col, "Yêu cầu hệ thống");
        Table(col,
            new[] { "Thành phần", "Yêu cầu tối thiểu" },
            new[]
            {
                new[] { "Hệ điều hành", "Windows 10 22H2 / Windows 11 22H2 trở lên (x64)" },
                new[] { "Quyền truy cập", "Local Administrator (UAC elevation bắt buộc)" },
                new[] { "RAM",         "4 GB (khuyến nghị 8 GB khi quét nhiều .evtx)" },
                new[] { "Ổ đĩa",       "Tối thiểu 500 MB trống cho evidence folder" },
                new[] { ".NET runtime", "Không cần — tự chứa trong single-file .exe" },
                new[] { "Network",     "Không bắt buộc (offline); cần khi dùng LAN Scanner hoặc đồng bộ CVE" }
            });

        Subheading(col, "Kiến trúc tổng thể");
        Paragraph(col,
            "Ứng dụng được tổ chức theo mô hình plugin — mỗi module là một project độc lập " +
            "triển khai interface IAuditModule. Shell WPF (SecAudit.App) điều phối các module " +
            "thông qua dependency injection. Một dự án CLI song song (SecAudit.Cli) dùng chung " +
            "toàn bộ lớp module nhưng bỏ WPF — phục vụ quét headless trong WinPE.");

        Subheading(col, "Cấu trúc giải pháp (solution)");
        MonoBlock(col,
            "src/\n" +
            "  SecAudit.App                        — WPF shell, NavigationView, 6 trang\n" +
            "  SecAudit.Cli                        — chạy headless + chế độ --offline\n" +
            "  SecAudit.Core                       — Finding, Severity, RiskScore\n" +
            "  SecAudit.Plugins.Abstractions       — IAuditModule, ModuleMetadata\n" +
            "  SecAudit.Infrastructure             — wrapper WMI / Registry / Process / Net\n" +
            "  SecAudit.Security                   — EulaGate, AuditLog (hash-chain + ECDSA)\n" +
            "  SecAudit.Reporting                  — HTML + PDF + DOCX + JSON writers\n" +
            "  SecAudit.Cve.Pipeline               — NVD downloader + CPE matcher\n" +
            "  SecAudit.Modules.SystemInfo         — Module 1\n" +
            "  SecAudit.Modules.Hardening          — Module 2 (12 CIS checks)\n" +
            "  SecAudit.Modules.PatchCve           — Module 3\n" +
            "  SecAudit.Modules.LanScanner         — Module 4\n" +
            "  SecAudit.Modules.RemoteAccess       — Module 5\n" +
            "  SecAudit.Modules.LogForensics       — Module 6 (18 rule + 8 chain)\n" +
            "tools/SecAudit.DocGen                 — sinh tài liệu này");

        Subheading(col, "Cây dữ liệu runtime (tạo lần đầu chạy)");
        MonoBlock(col,
            "%LOCALAPPDATA%\\SecAudit\\\n" +
            "  cve\\cve.db                         — CSDL NVD offline\n" +
            "  forensics\\<session-id>\\            — evidence folder mặc định\n" +
            "    originals\\                       — bản sao tệp log\n" +
            "    findings.json                    — kết quả chi tiết\n" +
            "    manifest.json                    — chain-of-custody SHA-256\n" +
            "  logs\\audit-YYYYMMDD.log            — sổ audit JSONL ký ECDSA\n" +
            "  eula-accepted                      — marker chấp thuận EULA");
    }

    // =========================================================================
    // 3. CÁC MODULE
    // =========================================================================
    private static void Section3_Modules(ColumnDescriptor col)
    {
        SectionTitle(col, "3. DANH SÁCH TÍNH NĂNG THEO MODULE");

        Paragraph(col,
            "SecAudit hiện có 6 module hoạt động độc lập, có thể chạy riêng rẽ hoặc chạy cả bộ. " +
            "Mỗi module sản sinh một tập hợp Finding với phân loại (category), mức độ nghiêm " +
            "trọng (severity) và phần evidence rõ ràng phục vụ kết luận giám định.");

        // ---- 3.1 System Info ----
        ModuleCard(col, "3.1  Module 1 — System Info & License",
            "Thu thập thông tin nhận dạng máy và tình trạng bản quyền phần mềm:",
            new[]
            {
                "HardwareInventory — CPU, RAM, ổ đĩa, BIOS serial (WMI).",
                "LicenseChecker — trạng thái kích hoạt Windows (Retail/KMS/MAK, Genuine).",
                "OfficeKmsPicoDetector — phát hiện dấu vết KMSpico và kích hoạt Office bất thường.",
                "SoftwareInventory — liệt kê phần mềm đã cài (HKLM\\Uninstall + HKCU + WOW6432Node)."
            },
            "Kết quả xuất vào SystemInventory chia sẻ để Hardening và PatchCve tái sử dụng.");

        // ---- 3.2 Hardening ----
        ModuleCard(col, "3.2  Module 2 — Hardening Audit (CIS-style)",
            "Gồm 12 check theo CIS Benchmark Microsoft Windows:",
            new[]
            {
                "UacCheck — User Account Control bật.",
                "SmbV1Check — SMB v1 đã tắt (MS17-010 surface).",
                "RdpNlaCheck — Network Level Authentication cho RDP.",
                "FirewallCheck — Windows Defender Firewall bật mọi profile.",
                "DefenderCheck — Defender real-time + signature up-to-date.",
                "BitLockerCheck — Mã hoá ổ hệ thống.",
                "GuestAccountCheck — Tài khoản Guest đã bị vô hiệu hoá.",
                "AutoRunCheck — Autostart trong HKLM Run / RunOnce sạch.",
                "LsaRunAsPplCheck — LSA Protected Process Light bật (chặn dump LSASS).",
                "PowerShellLoggingCheck — Script Block + Transcription logging bật.",
                "CredentialGuardCheck — VBS Credential Guard bật.",
                "HardeningModule — orchestrator chạy tất cả song song."
            },
            "Mỗi check trả về remediation cụ thể để bộ phận CNTT xử lý.");

        // ---- 3.3 PatchCve ----
        ModuleCard(col, "3.3  Module 3 — Patch & CVE Audit (offline)",
            "Đối chiếu inventory phần mềm đã cài với CSDL CVE offline:",
            new[]
            {
                "FastPathRules — 6 CVE nghiêm trọng: MS17-010, PrintNightmare, SMBGhost, " +
                    "Follina, BlueKeep, PetitPotam (không cần NVD).",
                "CveDatabase — SQLite NVD tại %LOCALAPPDATA%\\SecAudit\\cve\\cve.db.",
                "Matcher dùng NuGet.Versioning so khoảng version half-open.",
                "Cảnh báo khi CSDL cũ hơn 30 ngày (meta.last_sync)."
            },
            "Tìm ra các KB bị thiếu cho build Windows hiện tại.");

        // ---- 3.4 LAN Scanner ----
        ModuleCard(col, "3.4  Module 4 — LAN Scanner /24",
            "Khám phá và đánh giá rủi ro các host cùng mạng nội bộ — pure managed, không phụ thuộc Npcap:",
            new[]
            {
                "SubnetDiscovery — phát hiện /24 từ NetworkInterface cục bộ.",
                "HostDiscovery — ARP (iphlpapi.SendARP) + ICMP ping song song.",
                "PortScanner — TCP connect top 1000 port, timeout 500 ms, semaphore 256.",
                "SmbV1Probe — gửi gói SMB1 negotiate để fingerprint server SMBv1.",
                "RdpNlaProbe — X.224 + rdpNegReq để phát hiện RDP không NLA."
            },
            "Phạm vi quét tuân theo CIDR do người dùng cấu hình; không động vào host ngoài subnet.");

        // ---- 3.5 Remote Access ----
        ModuleCard(col, "3.5  Module 5 — Remote Access & Keylogger Detection",
            "Phát hiện 5 nhóm tín hiệu persistence / RAT — dựa trên registry, file, scheduled " +
            "task, WMI (không chạy memory scan để tránh AV false positive):",
            new[]
            {
                "PersistenceDetector — HKLM Run / RunOnce bất thường.",
                "WmiPersistenceDetector — __EventFilter / ActiveScriptEventConsumer / Binding " +
                    "(APT29 signature).",
                "ServicesHiveDetector — dịch vụ Windows trỏ path nghi vấn (%TEMP%, %APPDATA%).",
                "ScheduledTasksXmlDetector — Tasks XML có action -EncodedCommand, DownloadString.",
                "RemoteAccessToolDetector — TeamViewer, AnyDesk, RustDesk, VNC, QuickAssist."
            },
            "Module này nhiều false positive (admin tool hợp pháp), luôn đi kèm evidence để xác minh.");

        // ---- 3.6 Log Forensics ----
        col.Item().PageBreak();
        SectionTitle(col, "3.6  Module 6 — Log Forensics (chi tiết)");

        Paragraph(col,
            "Đây là module trung tâm của SecAudit — phân tích nhật ký Windows/Linux/Web để " +
            "tái tạo dòng sự kiện một cuộc tấn công. Module không chạy mặc định khi người dùng " +
            "nhấn Dashboard → nó đòi hỏi người phân tích cấu hình nguồn log cụ thể thông qua " +
            "trang \"Log Forensics\" (xem Chương 5).");

        Subheading(col, "8 Parser được hỗ trợ");
        Table(col,
            new[] { "Parser", "Định dạng" },
            new[]
            {
                new[] { "WindowsEvtxParser",    ".evtx (Windows Event Log nhị phân)" },
                new[] { "LinuxAuthLogParser",   "/var/log/auth.log" },
                new[] { "LinuxSyslogParser",    "/var/log/syslog" },
                new[] { "IisW3cLogParser",      "IIS W3C extended format" },
                new[] { "NginxAccessLogParser", "Nginx combined/main" },
                new[] { "ApacheErrorLogParser", "Apache error.log" },
                new[] { "BashHistoryParser",    "~/.bash_history" },
                new[] { "SysmonXmlParser",      "Sysmon event 1/3/7/8/10/11/13/22" }
            });

        Subheading(col, "18 rule phát hiện");
        Paragraph(col, "Nhóm Security log (9 rule) + nhóm Sysmon (10 rule):");
        Table(col,
            new[] { "Rule ID", "Phát hiện" },
            new[]
            {
                new[] { "FOR-BRUTE",       "≥10 logon thất bại cùng user/IP trong 5 phút" },
                new[] { "FOR-UNKNOWN",     "Logon bởi user ngoài whitelist baseline" },
                new[] { "FOR-SVC",         "Dịch vụ Windows lạ / path user-writable" },
                new[] { "FOR-CLEAR",       "Event log bị xoá / rsyslogd restart marker" },
                new[] { "FOR-SCAN",        "Scanner fingerprint (sqlmap, nikto, URL fan-out)" },
                new[] { "FOR-PRIVESC",     "sudo … bash -p, su sau auth fail, token manipulation" },
                new[] { "FOR-KEYLOGGER",   "Lệnh cài logkeys / debugger hook" },
                new[] { "FOR-RANSOM",      "Pattern mass-write file extension + shadow delete" },
                new[] { "FOR-WIPE",        "rm -rf --no-preserve-root, dd zero, vssadmin delete" },
                new[] { "SYSMON-LSASS",    "Process truy cập vào LSASS (mimikatz surface)" },
                new[] { "SYSMON-INJECT",   "CreateRemoteThread — process injection" },
                new[] { "SYSMON-SIDELOAD", "DLL sideload từ thư mục user-writable" },
                new[] { "SYSMON-PSENC",    "PowerShell -EncodedCommand / -enc / IEX DownloadString" },
                new[] { "SYSMON-PIPE",     "Named-pipe Cobalt Strike IoC (\\.\\pipe\\MSSE-…)" },
                new[] { "SYSMON-OFFICE-CHAIN", "WINWORD/EXCEL sinh cmd/powershell con" },
                new[] { "SYSMON-WMI",      "WMI Event Subscription được đăng ký mới" },
                new[] { "SYSMON-SC-CREATE","sc.exe create từ path đáng ngờ" },
                new[] { "SYSMON-LOLBIN-DL","certutil/bitsadmin/mshta tải file từ HTTP" },
                new[] { "SYSMON-DEFENDER-OFF", "Defender / EDR bị tắt / add-exclusion" }
            });

        Subheading(col, "8 Kill-chain MITRE ATT&CK (correlation)");
        Paragraph(col,
            "Correlation engine theo dõi tuần tự các finding và phát ra một finding nghiêm trọng " +
            "hơn khi nhiều rule cùng fire theo đúng trình tự + trong cửa sổ thời gian. Pivot là " +
            "Finding.Asset (host / user / process).");
        Table(col,
            new[] { "Chain ID", "Kịch bản", "Window" },
            new[]
            {
                new[] { "CHAIN-PHISH-EXEC",  "Office → PS enc → LOLBin download",            "5 phút" },
                new[] { "CHAIN-RANSOMWARE",  "Defender off → mass encrypt → xoá shadow",     "10 phút" },
                new[] { "CHAIN-CREDACCESS",  "LOLBin/PS → LSASS access/inject",              "10 phút" },
                new[] { "CHAIN-PERSIST-WMI", "PS/LOLBin → đăng ký WMI Event Subscription",   "10 phút" },
                new[] { "CHAIN-PERSIST-SVC", "PS/LOLBin → sc create dịch vụ từ user path",   "10 phút" },
                new[] { "CHAIN-LATERAL",     "Unknown/brute logon → privesc/LSASS",          "15 phút" },
                new[] { "CHAIN-INGRESS-C2",  "LOLBin → DLL sideload/inject → named pipe C2", "10 phút" },
                new[] { "CHAIN-DEFEVASION",  "Defender off → xoá event log",                 "30 phút" }
            });

        Subheading(col, "Bộ lọc khoảng thời gian (time window filter)");
        Paragraph(col,
            "Từ phiên bản này, Log Forensics cho phép giới hạn phạm vi phân tích theo thời " +
            "gian — phù hợp kịch bản phản ứng sự cố khi analyst đã biết khung giờ xảy ra. " +
            "Engine bỏ qua các bản ghi có timestamp ngoài khoảng [FromUtc, ToUtc], tiết kiệm " +
            "CPU đáng kể khi nhật ký dài 30 ngày nhưng chỉ quan tâm 2 giờ.");
        Bullets(col,
            "Preset sẵn: 1 giờ qua / 24 giờ qua / 7 ngày qua / 30 ngày qua / Xoá.",
            "Chỉnh tay: DatePicker + ô HH:mm cho mốc \"Từ\" và \"Đến\" (giờ local).",
            "Lọc áp dụng sau parse → an toàn với mọi định dạng (evtx, syslog, IIS...).",
            "Ghi vào audit log: from_utc, to_utc, skipped_by_window để kiểm toán.");
    }

    // =========================================================================
    // 4. GUI
    // =========================================================================
    private static void Section4_GuiUsage(ColumnDescriptor col)
    {
        SectionTitle(col, "4. HƯỚNG DẪN SỬ DỤNG GIAO DIỆN ĐỒ HOẠ");

        Subheading(col, "4.1  Khởi chạy lần đầu");
        OrderedList(col,
            "Copy SecAudit.exe sang máy cần kiểm tra (USB / chia sẻ nội bộ).",
            "Click chuột phải → Run as administrator. UAC sẽ hỏi — chọn Yes.",
            "Hộp thoại EULA hiện ra lần đầu: đánh 2 checkbox + gõ chuỗi I AM AUTHORIZED " +
                "(bắt buộc) để xác nhận có ủy quyền kiểm tra hợp pháp.",
            "Sau khi chấp thuận, shell chính hiện ra với NavigationView bên trái.");

        Subheading(col, "4.2  Cấu trúc giao diện");
        Bullets(col,
            "Dashboard — khởi chạy Full Audit 5 module (System/Hardening/Patch/LAN/Remote); " +
                "hiển thị tổng rủi ro, biểu đồ mức độ, lưới findings, nút xuất báo cáo.",
            "Log Forensics — trang chuyên biệt để cấu hình và chạy Module 6.",
            "Settings — nhập metadata báo cáo (tên đơn vị, người kiểm tra, khách hàng).",
            "Help — tài liệu tham chiếu nhanh.");

        Subheading(col, "4.3  Quy trình Dashboard (Full Audit)");
        OrderedList(col,
            "Nhấn \"Run Full Audit\" — 5 module chạy tuần tự.",
            "Theo dõi ProgressBar + đếm findings trên từng dòng module.",
            "Khi hoàn tất, lưới Findings hiển thị kết quả đã sắp theo severity.",
            "Nhấn \"Xuất báo cáo\" → chọn thư mục đích → 4 tệp sinh ra đồng thời " +
                "(HTML/PDF/DOCX/JSON).",
            "Mở thư mục evidence để xem manifest chain-of-custody.");

        Subheading(col, "4.4  Các điều khiển chung");
        Table(col,
            new[] { "Thao tác", "Hiệu ứng" },
            new[]
            {
                new[] { "Bắt đầu phân tích", "Khởi chạy module tương ứng với cấu hình hiện tại" },
                new[] { "Huỷ",               "Gửi CancellationToken — module dừng ở điểm an toàn" },
                new[] { "Mở thư mục bằng chứng", "Mở Explorer trỏ vào evidence folder của phiên" },
                new[] { "Xuất báo cáo",      "Sinh đồng thời 4 định dạng trong thư mục lưu trữ" }
            });
    }

    // =========================================================================
    // 5. LOG FORENSICS WORKFLOW
    // =========================================================================
    private static void Section5_LogForensicsWorkflow(ColumnDescriptor col)
    {
        SectionTitle(col, "5. QUY TRÌNH CHUẨN: LOG FORENSICS END-TO-END");

        Paragraph(col,
            "Chương này mô tả chuẩn quy trình phân tích một máy nghi bị xâm nhập. Giả định " +
            "analyst đã thu thập các .evtx và /var/log vào thư mục D:\\Evidence\\Case-2026-042.");

        Subheading(col, "Bước 1 — Chọn nguồn log");
        Bullets(col,
            "Tab \"Thư mục / tệp local\" — trỏ vào D:\\Evidence\\Case-2026-042 và bật \"Quét đệ quy\".",
            "Tab \"Windows Event Log\" — nhập channel Security/System để quét live (cần admin).",
            "Tab \"SSH / SFTP remote\" — nhập host + username + khoá riêng; cấu hình RemotePath=/var/log.");

        Subheading(col, "Bước 2 — Baseline & CIDR nội bộ");
        Bullets(col,
            "User whitelist: nhập chính xác các tài khoản được phép (vd: admin,root,dev). " +
                "Bất kỳ tên đăng nhập khác sẽ bị flag là logon lạ.",
            "Internal CIDR: mặc định 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 — sửa nếu cần.",
            "Evidence folder: để trống để dùng %LOCALAPPDATA%\\SecAudit\\forensics; hoặc chọn " +
                "một thư mục riêng (vd D:\\Forensics\\Case-2026-042).");

        Subheading(col, "Bước 3 — Giới hạn khoảng thời gian (NEW)");
        Paragraph(col,
            "Đây là bước quan trọng nhất để rút ngắn thời gian phân tích. Bật checkbox \"Giới " +
            "hạn khoảng thời gian\" ở góc phải Card. Có 4 preset nhanh hoặc nhập tay:");
        OrderedList(col,
            "Preset: nhấn 1 giờ qua / 24 giờ qua / 7 ngày qua / 30 ngày qua theo mức chuẩn IR.",
            "Nhập tay: chọn DatePicker cho ngày; ô bên cạnh gõ giờ phút dạng HH:mm (vd 14:30).",
            "Hệ thống quy đổi giờ local → UTC, validate Từ ≤ Đến.",
            "Engine sẽ loại bỏ bản ghi có timestamp ngoài khoảng ngay sau parse.");

        Subheading(col, "Bước 4 — Bắt đầu phân tích");
        OrderedList(col,
            "Nhấn nút \"Bắt đầu phân tích\" (màu xanh, bên trái hàng nút điều khiển).",
            "Theo dõi ProgressBar và 2 bộ đếm: Files (số tệp đã xử lý) và Records (số bản ghi đã parse).",
            "Trường \"Evidence:\" hiển thị đường dẫn phiên đang chạy — bản sao log gốc được lưu tại đây.",
            "Có thể nhấn \"Huỷ\" bất kỳ lúc nào — tiến trình dừng an toàn, báo cáo vẫn xuất được.");

        Subheading(col, "Bước 5 — Đọc kết quả");
        Bullets(col,
            "Tab \"Phát hiện\" — DataGrid cột Severity / Category / Title / Asset / Evidence.",
            "Tab \"Chain-of-custody\" — danh sách tệp log kèm SHA-256 làm bằng chứng pháp lý.",
            "Kill-chain finding hiển thị category = log-forensics.kill-chain, severity = Critical; " +
                "evidence liệt kê đầy đủ các stage theo thứ tự thời gian.");

        Subheading(col, "Bước 6 — Xuất báo cáo");
        Paragraph(col,
            "Nhấn \"Xuất báo cáo (PDF/DOCX/HTML/JSON)\". Hộp thoại ReportMetadata yêu cầu nhập:");
        Bullets(col,
            "Tên đơn vị kiểm tra (ví dụ: Công an tỉnh Sơn La).",
            "Tên người thực hiện + chức vụ.",
            "Tên khách hàng / chủ thể bị kiểm tra.",
            "Địa điểm + số hiệu biên bản.");
        Paragraph(col,
            "Báo cáo PDF theo mẫu \"BIÊN BẢN GHI NHẬN\" — format chuẩn cho hồ sơ pháp lý. DOCX " +
            "cho phép chỉnh sửa thêm. HTML mở nhanh trong trình duyệt. JSON dùng để tích hợp " +
            "ngược vào SIEM hoặc case-management.");
    }

    // =========================================================================
    // 6. CLI
    // =========================================================================
    private static void Section6_Cli(ColumnDescriptor col)
    {
        SectionTitle(col, "6. CHẾ ĐỘ DÒNG LỆNH (CLI) & KỊCH BẢN WINPE OFFLINE");

        Paragraph(col,
            "SecAudit.Cli là binary song song với SecAudit.App — dùng chung toàn bộ module nhưng " +
            "không phụ thuộc WPF, chạy được trên Windows PE / Hiren's BootCD PE / Gandalf's Win10 PE. " +
            "Phù hợp kịch bản điều tra máy đã tắt: boot USB WinPE, gắn ổ cứng Windows của máy mục " +
            "tiêu, chạy SecAudit.Cli.exe --offline D:\\");

        Subheading(col, "Cú pháp");
        MonoBlock(col, "SecAudit.Cli.exe [--offline <drive>] [--output <dir>] [--asset <name>]\n" +
                       "                  [--formats <csv>] [--quiet] [-h|--help]");

        Subheading(col, "Cờ được hỗ trợ");
        Table(col,
            new[] { "Cờ", "Ý nghĩa" },
            new[]
            {
                new[] { "--offline <drive>", "Quét ổ Windows đã được mount (vd D:\\). Tự đọc " +
                                             "winevt\\Logs; chỉ chạy PatchCve, RemoteAccess, LogForensics." },
                new[] { "--output <dir>",    "Thư mục ghi báo cáo (mặc định thư mục hiện tại)." },
                new[] { "--asset <name>",    "Ghi đè tên tài sản trong báo cáo " +
                                             "(mặc định %COMPUTERNAME% hoặc <drive>-OFFLINE)." },
                new[] { "--formats <csv>",   "Tập con trong {html,pdf,json,docx} (mặc định cả 4)." },
                new[] { "--quiet",           "Ẩn progress; chỉ in lỗi." },
                new[] { "-h, --help",        "Hiển thị hướng dẫn nhanh." }
            });

        Subheading(col, "Mã trả về (exit code)");
        Table(col,
            new[] { "Code", "Ý nghĩa" },
            new[]
            {
                new[] { "0",  "Thành công — báo cáo đã sinh." },
                new[] { "2",  "Module báo lỗi nhưng tiếp tục chạy được." },
                new[] { "3",  "Lỗi không xử lý được (unhandled exception)." },
                new[] { "64", "Cờ sai — kiểm tra lại cú pháp." }
            });

        Subheading(col, "Ví dụ thực tế");
        MonoBlock(col,
            "# Quét live máy đang chạy, chỉ xuất PDF + JSON:\n" +
            "SecAudit.Cli.exe --formats pdf,json --output D:\\Reports\n\n" +
            "# Quét offline ổ Windows tháo ra, gắn ở D:\\, tên asset = DESKTOP-KT07:\n" +
            "SecAudit.Cli.exe --offline D:\\ --asset DESKTOP-KT07 --output E:\\Case-042\n\n" +
            "# Dùng trong script PowerShell, ẩn progress:\n" +
            "& \"C:\\Tools\\SecAudit.Cli.exe\" --offline F:\\ --quiet --formats json\n" +
            "if ($LASTEXITCODE -ne 0) { Write-Error \"Scan failed\" }");

        Subheading(col, "Kịch bản WinPE (USB điều tra)");
        OrderedList(col,
            "Boot máy mục tiêu từ USB WinPE (Hiren's / Gandalf's).",
            "Trong WinPE, gắn ổ cứng Windows → thường là D:\\ hoặc F:\\",
            "Chạy SecAudit.Cli.exe từ USB khác (chỉ 1 tệp, không cần cài đặt).",
            "Kết quả ghi ra thư mục --output; copy báo cáo về USB trả lại người yêu cầu.",
            "Máy mục tiêu KHÔNG thay đổi gì — ổ đĩa chỉ được đọc.");
    }

    // =========================================================================
    // 7. REPORT
    // =========================================================================
    private static void Section7_Reports(ColumnDescriptor col)
    {
        SectionTitle(col, "7. BÁO CÁO: HTML / PDF / DOCX / JSON");

        Table(col,
            new[] { "Định dạng", "Writer", "Dùng khi nào" },
            new[]
            {
                new[] { "HTML",  "HtmlReportWriter", "Xem nhanh trên trình duyệt; chia sẻ nội bộ." },
                new[] { "PDF",   "PdfReportWriter (QuestPDF)", "Biên bản pháp lý — có chữ ký đóng dấu." },
                new[] { "DOCX",  "DocxReportWriter (OpenXml)", "Cần chỉnh sửa thêm trước khi nộp." },
                new[] { "JSON",  "JsonReportWriter", "Nhập vào SIEM / case management / backup máy." }
            });

        Subheading(col, "Nội dung tiêu biểu một báo cáo");
        Bullets(col,
            "Trang bìa: tên đơn vị, ngày giờ, tên máy, số hiệu biên bản.",
            "Tóm tắt điều hành: risk score tổng, biểu đồ pie severity, danh sách vấn đề nổi bật.",
            "Thông tin thiết bị: CPU, RAM, OS, BIOS serial, MAC, IP.",
            "Danh sách findings nhóm theo module, màu severity.",
            "Phụ lục: evidence dài, manifest chain-of-custody SHA-256.",
            "Phần kết luận / ký tên theo mẫu biên bản công tác.");

        Subheading(col, "Vị trí lưu trữ");
        MonoBlock(col,
            "<output-dir>\\\n" +
            "  report-YYYYMMDD-HHmmss.html\n" +
            "  report-YYYYMMDD-HHmmss.pdf\n" +
            "  report-YYYYMMDD-HHmmss.docx\n" +
            "  report-YYYYMMDD-HHmmss.json\n" +
            "  evidence\\manifest.json              (nếu có log forensics)\n" +
            "  evidence\\originals\\*.log.bak       (bản sao log gốc)");
    }

    // =========================================================================
    // 8. SECURITY / COMPLIANCE
    // =========================================================================
    private static void Section8_Security(ColumnDescriptor col)
    {
        SectionTitle(col, "8. BẢO MẬT, AUDIT LOG & TUÂN THỦ PHÁP LUẬT");

        Subheading(col, "8.1  EULA Gate");
        Paragraph(col,
            "Ngay khi khởi động, SecAudit hiển thị hộp thoại End-User License Agreement bằng " +
            "tiếng Việt và Anh, viện dẫn Luật An ninh mạng 2018 Điều 8 + Bộ luật Hình sự 2015 " +
            "Điều 289 (xâm nhập trái phép hệ thống thông tin). Người dùng buộc phải đánh 2 " +
            "checkbox và gõ chuỗi xác nhận \"I AM AUTHORIZED\" để qua gate. Tất cả sự kiện chấp " +
            "thuận được ghi vào audit log kèm SID, tên máy, dấu thời gian.");

        Subheading(col, "8.2  Audit log ký số");
        Paragraph(col,
            "Mọi thao tác nhạy cảm ghi vào %LOCALAPPDATA%\\SecAudit\\logs\\audit-YYYYMMDD.log " +
            "(JSONL append-only). Mỗi record có prev_hash SHA-256 tạo hash chain + chữ ký " +
            "ECDSA-P256. Khóa riêng được sinh lần đầu, bảo vệ bằng DPAPI LocalMachine scope, " +
            "lưu tại %LOCALAPPDATA%\\SecAudit\\keys\\audit.key. Khóa công khai nhúng trong binary.");

        Bullets(col,
            "Sự kiện bắt buộc log: start/stop mỗi module, EULA accepted, từ_utc / đến_utc " +
                "của forensics, xuất báo cáo, truy cập evidence folder.",
            "Sổ audit hiển thị được bằng công cụ verify đi kèm — phát hiện mọi chỉnh sửa trái phép.");

        Subheading(col, "8.3  Integrity check khởi động");
        Paragraph(col,
            "Khi chạy, SecAudit tự kiểm SHA-256 của tệp .exe so với hash nhúng lúc publish. " +
            "Nếu mismatch (nghi bị sửa đổi), các module nhạy cảm bị tắt, banner đỏ cảnh báo " +
            "trên shell; chỉ cho phép chạy module read-only.");

        Subheading(col, "8.4  Chain-of-custody log forensics");
        Paragraph(col,
            "Mỗi phiên Log Forensics sinh manifest.json liệt kê từng tệp log gốc đã quét với " +
            "SHA-256, kích thước, đường dẫn gốc, và hash chain. Tài liệu này đính kèm báo cáo " +
            "giám định để tòa án xác minh tính toàn vẹn bằng chứng.");

        Subheading(col, "8.5  Lưu ý quan trọng — pháp lý");
        NoteBox(col,
            "Chỉ sử dụng SecAudit trên máy tính và hệ thống mạng mà bạn có quyền truy cập hợp " +
            "pháp. Kiểm thử mật khẩu yếu không được phép thực hiện trên tài khoản domain. " +
            "Kịch bản LAN Scanner có opt-in probe default-creds — chỉ bật trên phòng lab nội " +
            "bộ với biên bản ủy quyền kiểm thử. Vi phạm có thể cấu thành tội danh theo BLHS Điều 289.");
    }

    // =========================================================================
    // 9. FAQ
    // =========================================================================
    private static void Section9_Faq(ColumnDescriptor col)
    {
        SectionTitle(col, "9. CÂU HỎI THƯỜNG GẶP & XỬ LÝ SỰ CỐ");

        Faq(col,
            "Windows Defender báo đỏ khi chạy SecAudit.exe",
            "SecAudit có chứa code đọc registry, WMI, và P/Invoke iphlpapi — dễ bị heuristic " +
            "nhầm với công cụ tấn công. Bản chính thức được ký OV code-signing và gửi Microsoft " +
            "WDSI sau mỗi release. Nếu dùng trong môi trường doanh nghiệp, thêm exclusion cho " +
            "đường dẫn tệp. Tuyệt đối KHÔNG dùng bản không ký.");

        Faq(col,
            "Không thấy nút \"Bắt đầu phân tích\" trên trang Log Forensics",
            "Đã sửa trong phiên bản hiện tại — layout được cấu trúc lại với DockPanel: phần cấu " +
            "hình có thể cuộn, hàng nút + progress + findings luôn hiển thị. Nếu vẫn không thấy, " +
            "hãy phóng to cửa sổ lên ≥ 1280×720 hoặc cuộn phần cấu hình lên trên.");

        Faq(col,
            "Thời gian quét quá lâu khi log dài 30 ngày",
            "Bật checkbox \"Giới hạn khoảng thời gian\" trên trang Log Forensics. Dùng preset " +
            "\"24 giờ qua\" hoặc nhập khung giờ bạn nghi xảy ra sự cố. Engine sẽ lọc bỏ bản ghi " +
            "ngoài khoảng NGAY SAU khi parse, tiết kiệm 90%+ CPU trong phần analysis.");

        Faq(col,
            "CSDL CVE hiển thị cảnh báo \"cũ hơn 30 ngày\"",
            "Click nút \"Update CVE database\" trong module Patch/CVE để đồng bộ NVD (cần " +
            "Internet). Trong môi trường air-gap, tải thủ công NVD JSON feed và thay thế " +
            "%LOCALAPPDATA%\\SecAudit\\cve\\cve.db bằng file do đội security center cấp.");

        Faq(col,
            "Làm sao verify một báo cáo PDF không bị sửa đổi?",
            "Mỗi báo cáo đi kèm SHA-256 in ở chân trang và một entry tương ứng trong audit log " +
            "đã ký ECDSA. Chạy công cụ verify đi kèm để so sánh hash. Ngoài ra chain-of-custody " +
            "manifest.json chứa hash các tệp log gốc — không thể bị chỉnh sửa mà không phát hiện.");

        Faq(col,
            "Kill-chain finding không xuất hiện dù các rule thành phần đều fire",
            "Kiểm tra ba điều kiện: (1) các finding phải có cùng pivot (cùng Asset, vd cùng " +
            "host:TEST-01); (2) tuần tự đúng thứ tự các stage của chain; (3) toàn bộ trong " +
            "cửa sổ thời gian của chain (xem bảng 8 chain). Nếu out-of-order, engine sẽ reset " +
            "tiến độ khi thấy stage 0 mới.");

        Faq(col,
            "SSH remote báo lỗi authentication",
            "Ưu tiên xác thực khoá riêng (Private key) hơn password. Nếu khoá có passphrase, " +
            "nhập vào ô SshPrivateKeyPassphrase (ẩn trong UI). Đảm bảo user có quyền đọc " +
            "/var/log/auth.log (nhóm adm trên Ubuntu, nhóm systemd-journal trên RHEL).");

        Faq(col,
            "Ổ đĩa offline không nhận diện được Windows",
            "--offline yêu cầu cấu trúc Windows chuẩn: <drive>\\Windows\\System32\\config\\SOFTWARE " +
            "và <drive>\\Windows\\System32\\winevt\\Logs. Nếu đĩa bị mã hoá BitLocker, phải unlock " +
            "trước trong WinPE (manage-bde -unlock) rồi mới chạy SecAudit.Cli.");

        col.Item().PaddingTop(20).AlignCenter().Text(
            "— HẾT —").FontSize(11).Bold().FontColor(Primary);
        col.Item().PaddingTop(4).AlignCenter().Text(
            "Liên hệ hỗ trợ: duonggiabao.anm@gmail.com")
            .FontSize(9.5f).FontColor(Muted);
    }

    // =========================================================================
    // HELPERS — primitive rendering
    // =========================================================================
    private static void SectionTitle(ColumnDescriptor col, string text)
    {
        col.Item().PaddingBottom(4).Row(r =>
        {
            r.ConstantItem(6).Background(Accent);
            r.RelativeItem().PaddingLeft(10).Text(text)
                .FontSize(18).Bold().FontColor(Primary);
        });
        col.Item().PaddingBottom(6).LineHorizontal(0.6f).LineColor(LightGray);
    }

    private static void Subheading(ColumnDescriptor col, string text) =>
        col.Item().PaddingTop(8).Text(text).FontSize(12).Bold().FontColor(Accent);

    private static void Paragraph(ColumnDescriptor col, string text) =>
        col.Item().Text(text).FontSize(10.5f).FontColor(DarkGray);

    private static void Bullets(ColumnDescriptor col, params string[] items)
    {
        foreach (var it in items)
        {
            col.Item().Row(r =>
            {
                r.ConstantItem(16).PaddingTop(2).Text("•").FontColor(Accent).Bold();
                r.RelativeItem().Text(it).FontSize(10.3f);
            });
        }
    }

    private static void OrderedList(ColumnDescriptor col, params string[] items)
    {
        int n = 1;
        foreach (var it in items)
        {
            int k = n++;
            col.Item().Row(r =>
            {
                r.ConstantItem(22).Text($"{k}.").FontColor(Primary).Bold();
                r.RelativeItem().Text(it).FontSize(10.3f);
            });
        }
    }

    private static void MonoBlock(ColumnDescriptor col, string text) =>
        col.Item().PaddingVertical(4).Background(SoftBg).Padding(10)
            .Text(text).FontFamily(Fonts.Consolas).FontSize(9).FontColor(DarkGray);

    private static void NoteBox(ColumnDescriptor col, string text) =>
        col.Item().PaddingVertical(6).Border(1).BorderColor(RedBad).Padding(10).Row(r =>
        {
            r.ConstantItem(24).AlignTop().Text("!").FontSize(16).Bold().FontColor(RedBad);
            r.RelativeItem().Text(text).FontSize(10).FontColor(DarkGray);
        });

    private static void Table(ColumnDescriptor col, string[] headers, string[][] rows)
    {
        col.Item().PaddingTop(4).Table(t =>
        {
            t.ColumnsDefinition(cd =>
            {
                foreach (var _ in headers)
                {
                    cd.RelativeColumn();
                }
            });
            t.Header(h =>
            {
                foreach (var text in headers)
                {
                    h.Cell().Background(Primary).Padding(6)
                        .Text(text).FontColor(Colors.White).Bold().FontSize(10);
                }
            });
            for (int i = 0; i < rows.Length; i++)
            {
                string bg = i % 2 == 0 ? Colors.White : SoftBg;
                foreach (var cell in rows[i])
                {
                    t.Cell().Background(bg).Padding(6)
                        .Text(cell).FontSize(9.5f).FontColor(DarkGray);
                }
            }
        });
    }

    private static void ModuleCard(ColumnDescriptor col, string title, string intro,
        string[] bullets, string closing)
    {
        col.Item().PaddingTop(10).Background(SoftBg).Padding(12).Column(inner =>
        {
            inner.Item().Text(title).FontSize(13).Bold().FontColor(Primary);
            inner.Item().PaddingTop(4).Text(intro).FontSize(10.3f);
            foreach (var b in bullets)
            {
                inner.Item().Row(r =>
                {
                    r.ConstantItem(14).PaddingTop(2).Text("◆").FontColor(Accent).FontSize(8);
                    r.RelativeItem().Text(b).FontSize(10);
                });
            }
            inner.Item().PaddingTop(4).Text(closing).Italic().FontSize(9.8f).FontColor(Muted);
        });
    }

    private static void Faq(ColumnDescriptor col, string question, string answer)
    {
        col.Item().PaddingTop(8).Column(inner =>
        {
            inner.Item().Row(r =>
            {
                r.ConstantItem(18).Text("Q.").Bold().FontColor(Primary);
                r.RelativeItem().Text(question).Bold().FontSize(10.5f).FontColor(DarkGray);
            });
            inner.Item().PaddingLeft(18).PaddingTop(2)
                .Text(answer).FontSize(10.2f).FontColor(DarkGray);
        });
    }
}
