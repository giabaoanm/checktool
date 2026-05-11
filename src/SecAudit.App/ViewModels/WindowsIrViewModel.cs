using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Browser;
using SecAudit.Modules.LogForensics.Office;
using SecAudit.Modules.LogForensics.Recent;
using SecAudit.Modules.LogForensics.WindowsIr;
using SecAudit.Security;

namespace SecAudit.App.ViewModels;

/// <summary>
/// One-shot Windows IR workflow: runs Browser, Office, Recent-Files modules
/// against the local C:\Users tree (or a copy from another machine), then
/// exports a unified PDF / Markdown / HTML report covering all 5 P1-P5 areas.
///
/// <para>AD-Attack and Ransomware-Precursor rules consume EVTX events through
/// the existing Log Forensics pipeline; their findings appear in the standard
/// audit report when LogForensics runs. This page focuses on the user-profile
/// artefacts that don't need EVTX collection.</para>
/// </summary>
public sealed partial class WindowsIrViewModel : ObservableObject, IDisposable
{
    private readonly BrowserForensicsAnalyzer _browser;
    private readonly OfficeArtifactsAnalyzer _office;
    private readonly RecentFilesAnalyzer _recent;
    private readonly EulaGate _eula;
    private readonly ILogger<WindowsIrViewModel> _log;
    private CancellationTokenSource? _cts;
    private List<Finding>? _lastFindings;
    private List<string>? _lastIocs;
    private int _lastFilesScanned;
    private string _lastSourcePath = string.Empty;

    public WindowsIrViewModel(
        BrowserForensicsAnalyzer browser,
        OfficeArtifactsAnalyzer office,
        RecentFilesAnalyzer recent,
        EulaGate eula,
        ILogger<WindowsIrViewModel> log)
    {
        _browser = browser;
        _office = office;
        _recent = recent;
        _eula = eula;
        _log = log;
    }

    public ObservableCollection<WindowsIrFindingRow> Findings { get; } = new();

    [ObservableProperty] private string _usersRoot = string.Empty;
    [ObservableProperty] private string _asset = Environment.MachineName;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _isRunning;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _hasResults;

    [ObservableProperty] private string _status =
        "Sẵn sàng. Mặc định quét C:\\Users của máy này. Hoặc bấm Duyệt để chỉ tới Users folder copy từ máy khác.";
    [ObservableProperty] private int _findingCount;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _iocCount;

    [RelayCommand]
    private void BrowsePath()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Chọn folder Users (C:\\Users) — của máy này hoặc copy từ máy khác"
        };
        if (!string.IsNullOrWhiteSpace(UsersRoot) && Directory.Exists(UsersRoot))
        {
            dlg.InitialDirectory = UsersRoot;
        }
        if (dlg.ShowDialog() == true)
        {
            UsersRoot = dlg.FolderName;
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

        var root = string.IsNullOrWhiteSpace(UsersRoot)
            ? Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "\\", "Users")
            : UsersRoot;
        if (!Directory.Exists(root))
        {
            MessageBox.Show("Đường dẫn Users không tồn tại: " + root,
                "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        IsRunning = true;
        HasResults = false;
        Findings.Clear();
        FindingCount = CriticalCount = HighCount = MediumCount = IocCount = 0;
        _lastFindings = null; _lastIocs = null; _lastFilesScanned = 0;
        _cts = new CancellationTokenSource();
        var asset = string.IsNullOrWhiteSpace(Asset) ? Environment.MachineName : Asset;

        try
        {
            var allFindings = new List<Finding>();
            var allIocs = new HashSet<string>(StringComparer.Ordinal);
            var totalScanned = 0;

            Status = "Đang quét Browser Forensics (Chrome/Edge/Firefox)...";
            var br = await Task.Run(() => _browser.AnalyzeHost(root, asset, _cts.Token), _cts.Token)
                .ConfigureAwait(true);
            allFindings.AddRange(br.Findings);
            foreach (var i in br.ExtractedIocs) { allIocs.Add(i); }
            totalScanned += br.ProfilesScanned;

            Status = "Đang quét Office Artifacts (Trusted Docs + macro + Outlook cache)...";
            var of = await Task.Run(() => _office.Analyze(root, asset, _cts.Token), _cts.Token)
                .ConfigureAwait(true);
            allFindings.AddRange(of.Findings);
            foreach (var i in of.ExtractedIocs) { allIocs.Add(i); }
            totalScanned += of.MacroFilesScanned + of.OutlookCacheFilesScanned;

            Status = "Đang quét Recent Files & JumpList...";
            var rc = await Task.Run(() => _recent.Analyze(root, asset, _cts.Token), _cts.Token)
                .ConfigureAwait(true);
            allFindings.AddRange(rc.Findings);
            foreach (var i in rc.ExtractedIocs) { allIocs.Add(i); }
            totalScanned += rc.LnkFilesParsed;

            _lastFindings = allFindings;
            _lastIocs = allIocs.ToList();
            _lastFilesScanned = totalScanned;
            _lastSourcePath = root;

            FindingCount = allFindings.Count;
            CriticalCount = allFindings.Count(f => f.Severity == Severity.Critical);
            HighCount = allFindings.Count(f => f.Severity == Severity.High);
            MediumCount = allFindings.Count(f => f.Severity == Severity.Medium);
            IocCount = allIocs.Count;

            foreach (var f in allFindings.OrderByDescending(f => f.Severity))
            {
                Findings.Add(new WindowsIrFindingRow(
                    f.Severity.ToString(),
                    CategoryFromId(f.Id),
                    f.Id,
                    f.Title,
                    Truncate(f.Evidence, 200)));
            }

            HasResults = allFindings.Count > 0;
            Status = HasResults
                ? $"✓ Hoàn tất — {totalScanned} mục quét, {allFindings.Count} finding ({CriticalCount} Critical, {HighCount} High), {allIocs.Count} IOC."
                : $"✓ Hoàn tất — không phát hiện finding nào ({totalScanned} mục đã quét).";
        }
        catch (OperationCanceledException) { Status = "Đã hủy."; }
        catch (Exception ex)
        {
            _log.LogError(ex, "Windows IR scan failed");
            Status = "Lỗi: " + ex.Message;
            MessageBox.Show(ex.Message, "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { IsRunning = false; }
    }

    private bool CanRun() => !IsRunning;

    [RelayCommand]
    private void Cancel() => _cts?.Cancel();

    [RelayCommand(CanExecute = nameof(CanExportReport))]
    private void ExportReport()
    {
        if (_lastFindings is null || _lastIocs is null) { return; }

        var defaultName = $"secaudit-windows-ir-{Asset}-{DateTime.Now:yyyyMMdd-HHmmss}";
        var dlg = new SaveFileDialog
        {
            Title = "Lưu báo cáo Windows IR",
            FileName = defaultName + ".pdf",
            Filter = "PDF (*.pdf)|*.pdf|Markdown (*.md)|*.md|Cả hai (.pdf + .md)|*.*",
            DefaultExt = ".pdf"
        };
        if (dlg.ShowDialog() != true) { return; }

        try
        {
            var ctx = new WindowsIrReportBuilder.ReportContext(
                Asset: string.IsNullOrWhiteSpace(Asset) ? Environment.MachineName : Asset,
                SourcePath: _lastSourcePath,
                GeneratedAt: DateTimeOffset.Now,
                AllFindings: _lastFindings,
                ExtractedIocs: _lastIocs,
                FilesScanned: _lastFilesScanned);

            var picked = dlg.FileName;
            var dir = Path.GetDirectoryName(picked) ?? Environment.CurrentDirectory;
            var stem = Path.GetFileNameWithoutExtension(picked);

            if (dlg.FilterIndex == 1) // PDF
            {
                var p = picked.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase) ? picked : picked + ".pdf";
                File.WriteAllBytes(p, WindowsIrPdfWriter.Render(ctx));
                Status = "✓ Đã xuất PDF: " + p;
            }
            else if (dlg.FilterIndex == 2) // MD
            {
                File.WriteAllText(picked, WindowsIrReportBuilder.BuildMarkdown(ctx));
                Status = "✓ Đã xuất Markdown: " + picked;
            }
            else // both
            {
                var pdfPath = Path.Combine(dir, stem + ".pdf");
                var mdPath = Path.Combine(dir, stem + ".md");
                File.WriteAllBytes(pdfPath, WindowsIrPdfWriter.Render(ctx));
                File.WriteAllText(mdPath, WindowsIrReportBuilder.BuildMarkdown(ctx));
                Status = $"✓ Đã xuất 2 báo cáo: {stem}.{{pdf,md}}";
            }

            try
            {
                Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + picked + "\"")
                { UseShellExecute = true });
            }
            catch { /* best effort */ }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Export Windows IR report failed");
            MessageBox.Show("Không xuất được báo cáo: " + ex.Message,
                "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private bool CanExportReport() => HasResults && !IsRunning;

    public void Dispose() { _cts?.Dispose(); _cts = null; }

    private static string CategoryFromId(string id)
    {
        if (id.StartsWith("BRW-", StringComparison.Ordinal)) { return "Browser"; }
        if (id.StartsWith("OFC-", StringComparison.Ordinal)) { return "Office"; }
        if (id.StartsWith("RCT-", StringComparison.Ordinal)) { return "Recent"; }
        if (id.StartsWith("FOR-AD-ATTACK-", StringComparison.Ordinal)) { return "AD-Attack"; }
        if (id.StartsWith("FOR-RANSOM-PRE-", StringComparison.Ordinal)) { return "Ransom-Pre"; }
        return "Other";
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

public sealed record WindowsIrFindingRow(
    string Severity, string Category, string Id, string Title, string EvidenceShort);
