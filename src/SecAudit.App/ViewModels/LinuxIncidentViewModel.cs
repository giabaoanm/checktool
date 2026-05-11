using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.LinuxIncident;
using SecAudit.Security;

namespace SecAudit.App.ViewModels;

/// <summary>
/// VM cho trang "Ứng cứu sự cố Linux / OCI". Cho phép user chỉ tới một rootfs đã
/// extract HOẶC một OCI image bundle (Docker save / containerd export). Tự động
/// bóc bundle vào thư mục tạm trước khi quét. Hỗ trợ:
///
/// <list type="bullet">
///   <item>Phát hiện SSH brute-force + đăng nhập password đáng ngờ trong auth.log
///         (kể cả file đã rotate <c>auth.log.*.gz</c>)</item>
///   <item>Soát NOPASSWD trong /etc/sudoers + sudoers.d/*</item>
///   <item>Cron persistence (hidden binary, @reboot, curl|sh, base64 obfuscation)</item>
///   <item>Ransom note tiếng Việt + tiếng Anh + đếm file đuôi mã hoá</item>
///   <item>IOC sweep (IPv4 public, BTC, email, URL) trên mọi text artifact</item>
/// </list>
/// </summary>
public sealed partial class LinuxIncidentViewModel : ObservableObject, IDisposable
{
    private readonly OciImageExtractor _extractor;
    private readonly LinuxIncidentAnalyzer _analyzer;
    private readonly EulaGate _eula;
    private readonly ILogger<LinuxIncidentViewModel> _log;
    private CancellationTokenSource? _cts;
    private LinuxIncidentAnalyzer.AnalysisResult? _lastResult;
    private string _lastSourcePath = string.Empty;

    public LinuxIncidentViewModel(
        OciImageExtractor extractor,
        LinuxIncidentAnalyzer analyzer,
        EulaGate eula,
        ILogger<LinuxIncidentViewModel> log)
    {
        _extractor = extractor;
        _analyzer = analyzer;
        _eula = eula;
        _log = log;
    }

    public ObservableCollection<LinuxFindingRow> Findings { get; } = new();
    public ObservableCollection<string> Iocs { get; } = new();

    [ObservableProperty] private string _path = string.Empty;
    [ObservableProperty] private string _asset = "DAVE";
    [ObservableProperty] private bool _cleanupAfterScan;
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private bool _isRunning;
    [ObservableProperty] private string _status =
        "Sẵn sàng. Chỉ tới rootfs Linux đã extract, hoặc folder OCI image bundle (Docker save). "
        + "Ứng dụng sẽ tự bóc image, quét sâu các tệp nén/mã hóa và liệt kê IOC.";
    [ObservableProperty] private int _filesScanned;
    [ObservableProperty] private int _findingCount;
    [ObservableProperty] private int _iocCount;
    [ObservableProperty] private string _detectedKind = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _hasResults;

    [RelayCommand]
    private void BrowsePath()
    {
        // Folder picker first — most common case is a rootfs / OCI bundle.
        var folderDlg = new OpenFolderDialog
        {
            Title = "Chọn rootfs Linux, OCI image bundle, hoặc bấm Cancel để chọn file archive (.tar.gz/.zip)"
        };
        if (!string.IsNullOrWhiteSpace(Path) && Directory.Exists(Path))
        {
            folderDlg.InitialDirectory = Path;
        }
        if (folderDlg.ShowDialog() == true)
        {
            Path = folderDlg.FolderName;
            UpdateDetectedKind();
            return;
        }

        // Fallback: file picker for single-archive input.
        var fileDlg = new OpenFileDialog
        {
            Title = "Chọn archive Linux (.tar / .tar.gz / .tgz / .zip)",
            Filter = "Archives (*.tar;*.tar.gz;*.tgz;*.zip)|*.tar;*.tar.gz;*.tgz;*.zip|All files|*.*"
        };
        if (fileDlg.ShowDialog() == true)
        {
            Path = fileDlg.FileName;
            UpdateDetectedKind();
        }
    }

    private void UpdateDetectedKind()
    {
        if (string.IsNullOrWhiteSpace(Path))
        {
            DetectedKind = string.Empty;
            return;
        }
        if (Directory.Exists(Path))
        {
            DetectedKind = OciImageExtractor.LooksLikeOciBundle(Path)
                ? "Đã nhận diện: OCI image bundle (sẽ tự bóc)"
                : "Đã nhận diện: rootfs/folder thông thường";
            return;
        }
        if (File.Exists(Path))
        {
            var kind = ArchiveExtractor.Detect(Path);
            DetectedKind = kind == ArchiveExtractor.ArchiveKind.None
                ? "⚠ File không nhận diện được định dạng — chỉ hỗ trợ .tar/.tar.gz/.tgz/.zip"
                : $"Đã nhận diện: archive {kind} (sẽ tự giải nén)";
        }
    }

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        if (!_eula.IsAccepted())
        {
            MessageBox.Show("Vui lòng chấp nhận EULA trước khi sử dụng module này.",
                "EULA", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(Path) || !Directory.Exists(Path))
        {
            MessageBox.Show("Đường dẫn không hợp lệ.", "Lỗi",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        IsRunning = true;
        HasResults = false;
        _lastResult = null;
        Findings.Clear();
        Iocs.Clear();
        FilesScanned = 0;
        FindingCount = 0;
        IocCount = 0;
        Status = "Đang chuẩn bị...";
        _cts = new CancellationTokenSource();

        string? tempDir = null;
        try
        {
            var rootfs = Path;
            if (OciImageExtractor.LooksLikeOciBundle(Path))
            {
                Status = "Đang bóc OCI image bundle vào thư mục tạm...";
                tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                    "secaudit-oci-" + Guid.NewGuid().ToString("N")[..12]);
                await Task.Run(() => _extractor.Extract(Path, tempDir, _cts.Token), _cts.Token)
                    .ConfigureAwait(true);
                rootfs = tempDir;
                Status = $"Đã bóc xong. Đang quét rootfs tại {tempDir}...";
            }
            else
            {
                Status = "Đang quét rootfs...";
            }

            var asset = string.IsNullOrWhiteSpace(Asset) ? "Linux-IR" : Asset;
            var result = await Task.Run(
                () => _analyzer.Analyze(rootfs, asset, _cts.Token), _cts.Token)
                .ConfigureAwait(true);

            _lastResult = result;
            _lastSourcePath = Path;
            FilesScanned = result.FilesScanned;
            FindingCount = result.Findings.Count;
            IocCount = result.ExtractedIocs.Count;
            HasResults = result.Findings.Count > 0 || result.ExtractedIocs.Count > 0;

            foreach (var f in result.Findings.OrderByDescending(f => f.Severity))
            {
                Findings.Add(new LinuxFindingRow(
                    f.Severity.ToString(),
                    f.Id,
                    f.Title,
                    string.Join(", ", f.AttackTechniqueIds),
                    Truncate(f.Evidence, 240),
                    f.Remediation));
            }
            foreach (var i in result.ExtractedIocs.OrderBy(i => i, StringComparer.Ordinal))
            {
                Iocs.Add(i);
            }

            Status = result.FilesScanned == 0
                ? "⚠ Đã quét nhưng không tìm thấy artifact Linux quen thuộc — kiểm tra lại đường dẫn."
                : $"✓ Hoàn tất — {result.FilesScanned} tệp quét, {result.Findings.Count} finding, {result.ExtractedIocs.Count} IOC.";
        }
        catch (OperationCanceledException)
        {
            Status = "Đã hủy.";
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Linux incident scan failed");
            Status = "Lỗi: " + ex.Message;
            MessageBox.Show(ex.Message, "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsRunning = false;
            if (tempDir is not null && CleanupAfterScan && Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, recursive: true); }
                catch { /* best effort */ }
            }
        }
    }

    private bool CanRun() => !IsRunning;

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
    }

    [RelayCommand(CanExecute = nameof(CanExportReport))]
    private void ExportReport()
    {
        if (_lastResult is null)
        {
            return;
        }
        var defaultName = $"secaudit-linux-{Asset}-{DateTime.Now:yyyyMMdd-HHmmss}";
        var dlg = new SaveFileDialog
        {
            Title = "Lưu báo cáo điều tra Linux",
            FileName = defaultName + ".pdf",
            Filter = "PDF (*.pdf)|*.pdf|Markdown (*.md)|*.md|HTML (*.html)|*.html|Cả ba (.pdf + .md + .html)|*.*",
            DefaultExt = ".pdf"
        };
        if (dlg.ShowDialog() != true)
        {
            return;
        }
        try
        {
            var ctx = new LinuxIncidentReportBuilder.ReportContext(
                Asset: string.IsNullOrWhiteSpace(Asset) ? "Linux-IR" : Asset,
                SourcePath: _lastSourcePath,
                GeneratedAt: DateTimeOffset.Now,
                Result: _lastResult);

            var picked = dlg.FileName;
            var dir = System.IO.Path.GetDirectoryName(picked) ?? Environment.CurrentDirectory;
            var stem = System.IO.Path.GetFileNameWithoutExtension(picked);

            if (dlg.FilterIndex == 1) // .pdf only
            {
                var p = picked.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase) ? picked : picked + ".pdf";
                File.WriteAllBytes(p, LinuxIncidentPdfWriter.Render(ctx));
                Status = "✓ Đã xuất báo cáo PDF: " + p;
            }
            else if (dlg.FilterIndex == 2) // .md only
            {
                File.WriteAllText(picked, LinuxIncidentReportBuilder.BuildMarkdown(ctx));
                Status = "✓ Đã xuất báo cáo Markdown: " + picked;
            }
            else if (dlg.FilterIndex == 3) // .html only
            {
                var p = picked.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ? picked : picked + ".html";
                File.WriteAllText(p, LinuxIncidentReportBuilder.BuildHtml(ctx));
                Status = "✓ Đã xuất báo cáo HTML: " + p;
            }
            else // all three
            {
                var pdfPath = System.IO.Path.Combine(dir, stem + ".pdf");
                var mdPath = System.IO.Path.Combine(dir, stem + ".md");
                var htmlPath = System.IO.Path.Combine(dir, stem + ".html");
                File.WriteAllBytes(pdfPath, LinuxIncidentPdfWriter.Render(ctx));
                File.WriteAllText(mdPath, LinuxIncidentReportBuilder.BuildMarkdown(ctx));
                File.WriteAllText(htmlPath, LinuxIncidentReportBuilder.BuildHtml(ctx));
                Status = $"✓ Đã xuất 3 báo cáo: {stem}.{{pdf,md,html}}";
            }

            // Open containing folder + select the file
            try
            {
                Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + picked + "\"")
                {
                    UseShellExecute = true
                });
            }
            catch { /* best effort */ }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Export Linux IR report failed");
            MessageBox.Show("Không xuất được báo cáo: " + ex.Message,
                "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private bool CanExportReport() => HasResults && !IsRunning;

    [RelayCommand]
    private void CopyIocs()
    {
        if (Iocs.Count == 0) { return; }
        try
        {
            Clipboard.SetText(string.Join(Environment.NewLine, Iocs));
            Status = $"Đã copy {Iocs.Count} IOC vào clipboard.";
        }
        catch
        {
            Status = "Không truy cập được clipboard.";
        }
    }

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";
}

public sealed record LinuxFindingRow(
    string Severity,
    string Id,
    string Title,
    string AttackTechniques,
    string EvidenceShort,
    string Remediation);
