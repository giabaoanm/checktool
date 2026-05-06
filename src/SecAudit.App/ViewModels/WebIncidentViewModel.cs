using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.App.Views.Dialogs;
using SecAudit.Core.Services;
using SecAudit.Modules.LogForensics.WebIncident;
using SecAudit.Plugins.Abstractions;
using SecAudit.Reporting;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;
using SecAudit.Security;

namespace SecAudit.App.ViewModels;

public sealed partial class WebIncidentViewModel : ObservableObject, IDisposable
{
    private readonly WebIncidentEvidenceCollector _collector;
    private readonly EulaGate _eula;
    private readonly ReportService _reports;
    private readonly ReportSettingsStore _settingsStore;
    private readonly RiskScoreCalculator _scorer;
    private readonly ILogger<WebIncidentViewModel> _log;
    private static readonly char[] AllowedHostSeparators = { ',', ';', '\r', '\n', '\t', ' ' };
    private CancellationTokenSource? _cts;
    private WebIncidentResult? _lastResult;

    public WebIncidentViewModel(
        WebIncidentEvidenceCollector collector,
        EulaGate eula,
        ReportService reports,
        ReportSettingsStore settingsStore,
        RiskScoreCalculator scorer,
        ILogger<WebIncidentViewModel> log)
    {
        _collector = collector;
        _eula = eula;
        _reports = reports;
        _settingsStore = settingsStore;
        _scorer = scorer;
        _log = log;
    }

    public ObservableCollection<WebIncidentFindingRow> Findings { get; } = new();
    public ObservableCollection<WebIncidentEvidenceRow> Manifest { get; } = new();
    public ObservableCollection<WebIncidentHttpRow> HttpObservations { get; } = new();
    public ObservableCollection<WebIncidentTimelineRow> Timeline { get; } = new();
    public ObservableCollection<WebIncidentLiveResourceRow> LiveResources { get; } = new();

    [ObservableProperty] private string _target = string.Empty;
    [ObservableProperty] private string _expectedContentSha256 = string.Empty;
    [ObservableProperty] private string _evidenceRootPath = string.Empty;
    [ObservableProperty] private string _serverEvidencePath = string.Empty;
    [ObservableProperty] private string _webRootPath = string.Empty;
    [ObservableProperty] private string _baselineManifestPath = string.Empty;
    [ObservableProperty] private int _timeoutSeconds = 15;
    [ObservableProperty] private int _maxBodyMb = 5;
    [ObservableProperty] private bool _probePlainHttp = true;
    [ObservableProperty] private bool _captureHttpBody;
    [ObservableProperty] private bool _enableLiveWebProbe;
    [ObservableProperty] private bool _safeLiveContentAnalysis = true;
    [ObservableProperty] private string _allowedExternalHosts = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _isRunning;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _hasResults;

    [ObservableProperty] private string _status = "Sẵn sàng. Mặc định chỉ phân tích evidence/log/webroot offline; bật Live URL probe nếu cần kết nối website.";
    [ObservableProperty] private string? _evidenceRoot;
    [ObservableProperty] private string? _sessionId;
    [ObservableProperty] private int _progressPercent;
    [ObservableProperty] private string _contentSha256 = string.Empty;
    [ObservableProperty] private string _pageTitle = string.Empty;

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
    }

    [RelayCommand]
    private void BrowseEvidenceRoot()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Chọn thư mục gốc lưu bằng chứng website",
            Multiselect = false
        };
        if (!string.IsNullOrWhiteSpace(EvidenceRootPath) && Directory.Exists(EvidenceRootPath))
        {
            dlg.InitialDirectory = EvidenceRootPath;
        }
        if (dlg.ShowDialog() == true)
        {
            EvidenceRootPath = dlg.FolderName;
        }
    }

    [RelayCommand]
    private void BrowseServerEvidence()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Chọn thư mục evidence server: access log, error log, webroot export",
            Multiselect = false
        };
        if (!string.IsNullOrWhiteSpace(ServerEvidencePath) && Directory.Exists(ServerEvidencePath))
        {
            dlg.InitialDirectory = ServerEvidencePath;
        }
        if (dlg.ShowDialog() == true)
        {
            ServerEvidencePath = dlg.FolderName;
        }
    }

    [RelayCommand]
    private void BrowseWebRoot()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Chọn thư mục webroot cần quét webshell/hash baseline",
            Multiselect = false
        };
        if (!string.IsNullOrWhiteSpace(WebRootPath) && Directory.Exists(WebRootPath))
        {
            dlg.InitialDirectory = WebRootPath;
        }
        if (dlg.ShowDialog() == true)
        {
            WebRootPath = dlg.FolderName;
        }
    }

    [RelayCommand]
    private void BrowseBaselineManifest()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn webroot-manifest.csv baseline sạch",
            Filter = "SecAudit webroot manifest|webroot-manifest.csv|CSV files|*.csv|All|*.*",
            CheckFileExists = true,
            CheckPathExists = true
        };
        if (dlg.ShowDialog() == true)
        {
            BaselineManifestPath = dlg.FileName;
        }
    }

    [RelayCommand]
    private async Task RunAsync()
    {
        if (IsRunning)
        {
            return;
        }
        var hasEvidenceInput = !string.IsNullOrWhiteSpace(ServerEvidencePath)
            || !string.IsNullOrWhiteSpace(WebRootPath)
            || !string.IsNullOrWhiteSpace(BaselineManifestPath);
        if (EnableLiveWebProbe && string.IsNullOrWhiteSpace(Target))
        {
            MessageBox.Show("Vui lòng nhập domain hoặc URL khi bật Live URL probe.",
                "SecAudit - Website incident", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!EnableLiveWebProbe && !hasEvidenceInput)
        {
            MessageBox.Show("Chế độ an toàn không kết nối Internet. Vui lòng chọn Evidence server, Webroot hoặc Baseline manifest; hoặc bật Live URL probe nếu cần kiểm tra URL trực tiếp.",
                "SecAudit - Website incident", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var confirmText = EnableLiveWebProbe
            ? "Chức năng này sẽ kết nối tới website/domain được nhập để thu thập DNS, TLS và HTTP header/status.\n\n"
              + "Mặc định SecAudit không tải/lưu nội dung trang. Nếu bật 'Thu nội dung HTML', ứng dụng sẽ đọc nội dung trang để kiểm tra deface/ransom marker.\n\n"
              + "Chỉ tiếp tục nếu bạn có thẩm quyền xử lý sự cố đối với mục tiêu này."
            : "Chế độ an toàn với antivirus sẽ KHÔNG kết nối tới website/domain. Ứng dụng chỉ phân tích evidence server, log, webroot hoặc baseline manifest đã chọn.\n\n"
              + "Chỉ tiếp tục nếu bạn có thẩm quyền xử lý sự cố đối với dữ liệu evidence này.";
        var confirm = MessageBox.Show(
            confirmText,
            "Xác nhận thẩm quyền - Website incident",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.OK)
        {
            return;
        }
        if (!_eula.IsAccepted())
        {
            MessageBox.Show("Vui lòng hoàn tất EULA trong mục Settings trước khi chạy chức năng này.",
                "EULA chưa được chấp nhận", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        Findings.Clear();
        Manifest.Clear();
        HttpObservations.Clear();
        Timeline.Clear();
        LiveResources.Clear();
        EvidenceRoot = null;
        SessionId = null;
        ContentSha256 = string.Empty;
        PageTitle = string.Empty;
        ProgressPercent = 0;
        HasResults = false;
        _lastResult = null;

        IsRunning = true;
        _cts = new CancellationTokenSource();
        var settings = new WebIncidentSettings
        {
            Targets = new[] { Target.Trim() },
            EvidenceRoot = EvidenceRootPath.Trim(),
            ServerEvidencePath = ServerEvidencePath.Trim(),
            WebRootPath = WebRootPath.Trim(),
            BaselineManifestPath = BaselineManifestPath.Trim(),
            ExpectedContentSha256 = ExpectedContentSha256.Trim(),
            TimeoutSeconds = Math.Clamp(TimeoutSeconds, 3, 120),
            MaxBodyBytes = Math.Clamp(MaxBodyMb, 1, 25) * 1024 * 1024,
            ProbePlainHttp = ProbePlainHttp,
            CaptureHttpBody = CaptureHttpBody,
            EnableLiveWebProbe = EnableLiveWebProbe,
            SafeLiveContentAnalysis = SafeLiveContentAnalysis,
            AllowedExternalHosts = SplitAllowedHosts(AllowedExternalHosts)
        };
        var progress = new Progress<WebIncidentProgress>(p =>
        {
            SessionId = p.SessionId;
            Status = p.Message;
            ProgressPercent = p.PercentComplete;
        });

        try
        {
            var result = await _collector.CollectAsync(Target, settings, progress, _cts.Token)
                .ConfigureAwait(true);
            _lastResult = result;
            EvidenceRoot = result.EvidenceRoot;
            PageTitle = result.ContentSignals?.Title ?? string.Empty;
            ContentSha256 = result.Http.Count == 0 ? string.Empty : result.Http[^1].BodySha256;

            foreach (var f in result.Findings)
            {
                Findings.Add(new WebIncidentFindingRow(
                    f.Id,
                    f.Title,
                    f.Severity.ToString(),
                    f.Category,
                    f.Asset,
                    f.Evidence));
            }
            foreach (var file in result.Manifest)
            {
                Manifest.Add(new WebIncidentEvidenceRow(
                    file.Name,
                    file.Kind,
                    file.SizeBytes,
                    file.Sha256,
                    file.LocalPath));
            }
            foreach (var http in result.Http)
            {
                HttpObservations.Add(new WebIncidentHttpRow(
                    http.Hop,
                    http.Url,
                    http.StatusCode?.ToString() ?? "ERR",
                    http.ElapsedMs,
                    http.RedirectLocation ?? string.Empty,
                    http.BodySha256,
                    http.Error ?? string.Empty));
            }
            foreach (var resource in result.LiveResources)
            {
                LiveResources.Add(new WebIncidentLiveResourceRow(
                    resource.Kind,
                    resource.IsExternal ? "External" : "Same-site",
                    resource.StatusCode?.ToString() ?? "ERR",
                    resource.Classification,
                    resource.BodySha256,
                    string.Join(", ", resource.Signals),
                    resource.Url,
                    resource.Error ?? string.Empty));
            }
            if (result.ServerEvidence?.Timeline is not null)
            {
                foreach (var e in result.ServerEvidence.Timeline)
                {
                    Timeline.Add(new WebIncidentTimelineRow(
                        e.Timestamp?.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty,
                        e.SourceIp,
                        e.Method,
                        e.Path,
                        e.StatusCode?.ToString() ?? string.Empty,
                        e.Rule,
                        e.SourceFile,
                        e.UserAgent));
                }
            }

            HasResults = true;
            Status = $"Xong. {result.Findings.Count} phát hiện, {result.Manifest.Count} file bằng chứng.";
        }
        catch (OperationCanceledException)
        {
            Status = "Đã hủy thu thập bằng chứng.";
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Web incident collection failed");
            Status = "Lỗi: " + ex.Message;
            MessageBox.Show(ex.Message, "SecAudit - Website incident", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsRunning = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
    }

    [RelayCommand]
    private void OpenEvidenceFolder()
    {
        if (string.IsNullOrWhiteSpace(EvidenceRoot) || !Directory.Exists(EvidenceRoot))
        {
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = EvidenceRoot,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Open web incident evidence folder failed");
        }
    }

    private bool CanExportReport() => !IsRunning && HasResults && _lastResult is not null;

    private static string[] SplitAllowedHosts(string value)
        => value.Split(AllowedHostSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    [RelayCommand(CanExecute = nameof(CanExportReport))]
    private async Task ExportReportAsync()
    {
        if (_lastResult is null)
        {
            return;
        }

        var currentSettings = _settingsStore.Load();
        var dialog = new ReportMetadataDialog(currentSettings)
        {
            Owner = Application.Current?.MainWindow
        };
        if (dialog.ShowDialog() != true || !dialog.ViewModel.Confirmed)
        {
            Status = "Đã hủy xuất báo cáo.";
            return;
        }
        var metadata = dialog.ViewModel.ToSettings();
        try
        {
            _settingsStore.Save(metadata);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to persist report metadata; continuing export anyway");
        }

        var picker = new OpenFolderDialog
        {
            Title = "Chọn thư mục lưu báo cáo sự cố website"
        };
        if (!string.IsNullOrWhiteSpace(EvidenceRoot) && Directory.Exists(EvidenceRoot))
        {
            picker.InitialDirectory = EvidenceRoot;
        }
        if (picker.ShowDialog() != true)
        {
            return;
        }

        try
        {
            Status = "Đang xuất báo cáo...";
            var aggregator = new FindingsAggregator();
            aggregator.Add(new ModuleResult
            {
                ModuleId = "web-incident",
                StartedAt = _lastResult.StartedAt,
                CompletedAt = _lastResult.CompletedAt,
                Succeeded = true,
                Findings = _lastResult.Findings.Cast<object>().ToList()
            });
            var score = _scorer.Score(_lastResult.Findings);
            var data = _reports.BuildData(
                aggregator,
                score,
                Environment.MachineName,
                DashboardHelpers.Build(null),
                Array.Empty<AppliedAction>(),
                metadata);
            var written = await Task.Run(
                () => _reports.WriteAllAsync(data, picker.FolderName, CancellationToken.None))
                .ConfigureAwait(true);
            Status = $"Đã xuất {written.Count} báo cáo vào {picker.FolderName}";
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Web incident report export failed");
            Status = "Lỗi xuất báo cáo: " + ex.Message;
            MessageBox.Show(ex.Message, "SecAudit - Xuất báo cáo", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}

public sealed record WebIncidentFindingRow(
    string Id,
    string Title,
    string Severity,
    string Category,
    string Asset,
    string Evidence);

public sealed record WebIncidentEvidenceRow(
    string Name,
    string Kind,
    long SizeBytes,
    string Sha256,
    string LocalPath);

public sealed record WebIncidentHttpRow(
    int Hop,
    string Url,
    string Status,
    long ElapsedMs,
    string RedirectLocation,
    string BodySha256,
    string Error);

public sealed record WebIncidentTimelineRow(
    string Time,
    string SourceIp,
    string Method,
    string Path,
    string Status,
    string Rule,
    string SourceFile,
    string UserAgent);

public sealed record WebIncidentLiveResourceRow(
    string Kind,
    string Scope,
    string Status,
    string Classification,
    string BodySha256,
    string Signals,
    string Url,
    string Error);
