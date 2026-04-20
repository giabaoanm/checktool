// -----------------------------------------------------------------------------
// SecAudit — Sinh tài liệu "Hướng dẫn sử dụng" dạng PDF tiếng Việt.
// Chạy: dotnet run --project tools/SecAudit.DocGen -- [out.pdf]
// Nếu bỏ qua tham số, tệp sẽ được ghi vào docs/SecAudit-HuongDan.pdf.
// -----------------------------------------------------------------------------

using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecAudit.DocGen;

QuestPDF.Settings.License = LicenseType.Community;

var output = args.Length > 0
    ? args[0]
    : Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "docs", "SecAudit-HuongDan.pdf");
output = Path.GetFullPath(output);
Directory.CreateDirectory(Path.GetDirectoryName(output)!);

Document.Create(UserGuide.Compose)
    .WithSettings(new DocumentSettings { PdfA = false })
    .GeneratePdf(output);

Console.WriteLine($"[OK] Đã sinh tài liệu: {output}");
Console.WriteLine($"     Kích thước: {new FileInfo(output).Length / 1024.0:F1} KB");
