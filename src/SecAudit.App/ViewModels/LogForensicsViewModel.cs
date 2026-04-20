using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.App.Views.Dialogs;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Plugins.Abstractions;
using SecAudit.Reporting;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;
using SecAudit.Security;

namespace SecAudit.App.ViewModels;

/// <summary>
/// Interactive view-model for Module 6 — Log Forensics. Unlike the other modules (which run
/// as part of "Run full audit"), this page collects per-job parameters (source kind + either
/// local path / EVTX channel / SSH credentials) and executes the engine directly. Findings
/// populate a secondary grid and the session's evidence root is revealed via a button so the
/// operator can forward the chain-of-custody bundle.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class LogForensicsViewModel : ObservableObject, IDisposable
{
    private readonly LogForensicsEngine _engine;
    private readonly EulaGate _eula;
    private readonly ReportService _reports;
    private readonly ReportSettingsStore _settingsStore;
    private readonly RiskScoreCalculator _scorer;
    private readonly ILogger<LogForensicsViewModel> _log;
    private CancellationTokenSource? _cts;

    /// <summary>
    /// Last engine result kept so "Xuất báo cáo" có thể dựng lại ReportData mà
    /// không cần chạy lại module. Null sau khi Clear hoặc chưa chạy lần nào.
    /// </summary>
    private ForensicsResult? _lastResult;

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
    }

    public LogForensicsViewModel(
        LogForensicsEngine engine,
        EulaGate eula,
        ReportService reports,
        ReportSettingsStore settingsStore,
        RiskScoreCalculator scorer,
        ILogger<LogForensicsViewModel> log)
    {
        _engine = engine;
        _eula = eula;
        _reports = reports;
        _settingsStore = settingsStore;
        _scorer = scorer;
        _log = log;
    }

    public ObservableCollection<LogForensicsFindingRow> Findings { get; } = new();
    public ObservableCollection<LogForensicsEvidenceRow> Manifest { get; } = new();

    // Source picker
    [ObservableProperty] private int _sourceKindIndex; // 0=LocalFolder, 1=WindowsEventLog, 2=SshRemote

    // Local folder
    [ObservableProperty] private string _localPath = string.Empty;
    [ObservableProperty] private bool _localRecursive = true;

    // Event log
    [ObservableProperty] private string _eventLogChannel = "Security";
    [ObservableProperty] private string? _evtxFile;

    // SSH
    [ObservableProperty] private string _sshHost = string.Empty;
    [ObservableProperty] private int _sshPort = 22;
    [ObservableProperty] private string _sshUsername = string.Empty;
    [ObservableProperty] private string? _sshPassword;
    [ObservableProperty] private string? _sshPrivateKeyPath;
    [ObservableProperty] private string? _sshPrivateKeyPassphrase;
    [ObservableProperty] private string _sshRemotePath = "/var/log/";
    [ObservableProperty] private bool _sshRecursive;

    // Common
    [ObservableProperty] private string _userWhitelist = string.Empty;
    [ObservableProperty] private string _internalCidrs = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12";

    // --- Time window ---
    // Khi analyst đã biết incident xảy ra quanh 14:00 hôm qua, quét toàn bộ log
    // 30 ngày là phí 99% CPU. FromDate/ToDate = ngày, FromTime/ToTime = HH:mm,
    // ghép thành DateTimeOffset tại local time rồi convert sang UTC khi chạy.
    // Default = không giới hạn (null).
    [ObservableProperty] private bool _useTimeRange;
    [ObservableProperty] private DateTime? _fromDate;
    [ObservableProperty] private string _fromTime = "00:00";
    [ObservableProperty] private DateTime? _toDate;
    [ObservableProperty] private string _toTime = "23:59";

    /// <summary>
    /// Presets tiện dụng — "1 giờ qua", "24 giờ qua", "7 ngày qua" đỡ analyst
    /// phải bấm picker cho các kịch bản IR thường gặp (incident vừa xảy ra).
    /// </summary>
    [RelayCommand]
    private void ApplyRangePreset(string preset)
    {
        var now = DateTime.Now;
        switch (preset)
        {
            case "1h":
                FromDate = now.AddHours(-1).Date;
                FromTime = now.AddHours(-1).ToString("HH:mm");
                ToDate = now.Date;
                ToTime = now.ToString("HH:mm");
                UseTimeRange = true;
                break;
            case "24h":
                FromDate = now.AddDays(-1).Date;
                FromTime = now.AddDays(-1).ToString("HH:mm");
                ToDate = now.Date;
                ToTime = now.ToString("HH:mm");
                UseTimeRange = true;
                break;
            case "7d":
                FromDate = now.AddDays(-7).Date;
                FromTime = "00:00";
                ToDate = now.Date;
                ToTime = "23:59";
                UseTimeRange = true;
                break;
            case "30d":
                FromDate = now.AddDays(-30).Date;
                FromTime = "00:00";
                ToDate = now.Date;
                ToTime = "23:59";
                UseTimeRange = true;
                break;
            case "clear":
                FromDate = null;
                ToDate = null;
                UseTimeRange = false;
                break;
        }
    }

    // Evidence output folder (user-chosen). Trống = engine tự tạo dưới %LOCALAPPDATA%.
    [ObservableProperty] private string _evidenceRootPath = string.Empty;

    // Run state
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _isRunning;
    [ObservableProperty] private string _status = "Sẵn sàng. Vui lòng chọn nguồn log.";
    [ObservableProperty] private int _filesProcessed;
    [ObservableProperty] private long _recordsProcessed;
    [ObservableProperty] private string? _evidenceRoot;
    [ObservableProperty] private string? _sessionId;

    /// <summary>
    /// True khi đã có một lần chạy hoàn tất (kể cả 0 phát hiện) — lúc đó mới cho
    /// phép export. Nếu 0 finding thì báo cáo vẫn được xuất để chứng nhận "đã quét
    /// nhưng không thấy vấn đề", phục vụ hồ sơ thanh tra.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportCommand))]
    private bool _hasResults;

    [RelayCommand]
    private void BrowseLocalPath()
    {
        // Pick MỘT tệp log đơn lẻ. Dùng khi chỉ cần phân tích 1 file riêng lẻ.
        var dlg = new OpenFileDialog
        {
            Title = "Chọn tệp log đơn lẻ để phân tích",
            Filter = "Log files|*.log;*.evtx;*.txt;*.out;*.syslog;*.access;*.error|All|*.*",
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false
        };
        if (dlg.ShowDialog() == true)
        {
            LocalPath = dlg.FileName;
        }
    }

    [RelayCommand]
    private void BrowseLocalFolder()
    {
        // Pick cả MỘT THƯ MỤC để quét hàng loạt — workflow chuẩn của SOC khi
        // cần phân tích toàn bộ /var/log hay C:\Logs. Nếu tick "Quét đệ quy"
        // thì engine sẽ đi sâu vào subfolder; mặc định true.
        var dlg = new OpenFolderDialog
        {
            Title = "Chọn thư mục chứa nhiều tệp log cần phân tích",
            Multiselect = false
        };
        if (!string.IsNullOrWhiteSpace(LocalPath) && Directory.Exists(LocalPath))
        {
            dlg.InitialDirectory = LocalPath;
        }
        if (dlg.ShowDialog() == true)
        {
            LocalPath = dlg.FolderName;
        }
    }

    [RelayCommand]
    private void BrowseEvtxFile()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn tệp .evtx đã snapshot",
            Filter = "Windows Event Log|*.evtx"
        };
        if (dlg.ShowDialog() == true)
        {
            EvtxFile = dlg.FileName;
        }
    }

    [RelayCommand]
    private void BrowseEvidenceRoot()
    {
        // .NET 8 bổ sung OpenFolderDialog gốc — không cần thư viện bên ngoài.
        var dlg = new OpenFolderDialog
        {
            Title = "Chọn thư mục lưu bằng chứng (evidence root)",
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
    private void BrowseSshKey()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn private key (OpenSSH / PEM)",
            Filter = "Private key|*.pem;*.key;id_rsa;id_ed25519|All|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            SshPrivateKeyPath = dlg.FileName;
        }
    }

    [RelayCommand]
    private async Task RunAsync()
    {
        if (IsRunning) { return; }

        // Legal gate — every log-forensics run requires explicit operator confirmation.
        var confirm = MessageBox.Show(
            "Module này sẽ thu thập và phân tích nhật ký trên hệ thống đích.\n\n"
            + "BẠN XÁC NHẬN có quyền quản trị hợp pháp trên hệ thống đang audit?\n"
            + "(Luật An ninh mạng số 116/2025/QH15 Điều 7 và BLHS Điều 289)",
            "Xác nhận quyền hạn — Log Forensics",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.OK) { return; }
        if (!_eula.IsAccepted())
        {
            MessageBox.Show("Vui lòng hoàn tất EULA trong mục Settings trước khi chạy module này.",
                "EULA chưa được chấp nhận", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        Findings.Clear();
        Manifest.Clear();
        FilesProcessed = 0;
        RecordsProcessed = 0;
        EvidenceRoot = null;
        SessionId = null;
        HasResults = false;
        _lastResult = null;

        // Nếu user đã chọn thư mục riêng, tạo subfolder theo session để không
        // trộn bằng chứng của các lần chạy khác nhau vào cùng chỗ.
        string? resolvedEvidenceRoot = null;
        if (!string.IsNullOrWhiteSpace(EvidenceRootPath))
        {
            var sessionSub = "session-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            resolvedEvidenceRoot = Path.Combine(EvidenceRootPath.Trim(), sessionSub);
        }

        // Build time window nếu user đã bật. TimeSpan.Parse "HH:mm" nhẹ hơn
        // TimePicker controls (WPF không có built-in TimePicker) và cho phép
        // analyst gõ trực tiếp "14:30".
        DateTimeOffset? fromUtc = null, toUtc = null;
        if (UseTimeRange)
        {
            if (FromDate.HasValue && TimeSpan.TryParse(FromTime, out var ft))
            {
                fromUtc = new DateTimeOffset(FromDate.Value.Date + ft, TimeZoneInfo.Local.GetUtcOffset(FromDate.Value.Date + ft))
                    .ToUniversalTime();
            }
            if (ToDate.HasValue && TimeSpan.TryParse(ToTime, out var tt))
            {
                toUtc = new DateTimeOffset(ToDate.Value.Date + tt, TimeZoneInfo.Local.GetUtcOffset(ToDate.Value.Date + tt))
                    .ToUniversalTime();
            }
            if (fromUtc.HasValue && toUtc.HasValue && fromUtc > toUtc)
            {
                MessageBox.Show(
                    "Thời gian bắt đầu > thời gian kết thúc. Vui lòng kiểm tra lại.",
                    "Khoảng thời gian không hợp lệ", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        var settings = new ForensicsSettings
        {
            SourceKind = (ForensicsSourceKind)SourceKindIndex,
            LocalPath = LocalPath,
            LocalRecursive = LocalRecursive,
            EventLogChannel = EventLogChannel,
            EvtxFile = EvtxFile,
            SshHost = SshHost,
            SshPort = SshPort,
            SshUsername = SshUsername,
            SshPassword = SshPassword,
            SshPrivateKeyPath = SshPrivateKeyPath,
            SshPrivateKeyPassphrase = SshPrivateKeyPassphrase,
            SshRemotePath = SshRemotePath,
            SshRecursive = SshRecursive,
            UserWhitelist = UserWhitelist,
            InternalCidrs = InternalCidrs,
            FromUtc = fromUtc,
            ToUtc = toUtc,
            EvidenceRoot = resolvedEvidenceRoot ?? string.Empty
        };

        IsRunning = true;
        _cts = new CancellationTokenSource();

        var progress = new Progress<ForensicsProgress>(p =>
        {
            FilesProcessed = p.FilesProcessed;
            RecordsProcessed = p.RecordsProcessed;
            Status = p.Message;
            SessionId ??= p.SessionId;
        });

        try
        {
            var result = await _engine.RunAsync(settings, progress, _cts.Token).ConfigureAwait(true);
            EvidenceRoot = result.EvidenceRoot;
            SessionId = result.SessionId;
            foreach (var f in result.Findings)
            {
                Findings.Add(new LogForensicsFindingRow(f.Title, f.Severity.ToString(), f.Category, f.Asset, f.Evidence));
            }
            foreach (var e in result.Manifest)
            {
                Manifest.Add(new LogForensicsEvidenceRow(
                    Path.GetFileName(e.LocalPath), e.OriginalPath, e.SizeBytes, e.Sha256));
            }
            _lastResult = result;
            HasResults = true;
            Status = $"Xong. {result.TotalFiles} tệp, {result.TotalRecords} bản ghi, {result.Findings.Count} phát hiện. Có thể xuất báo cáo PDF/DOCX/HTML/JSON.";
        }
        catch (OperationCanceledException)
        {
            Status = "Đã huỷ bởi người dùng.";
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "LogForensics run failed");
            Status = "Lỗi: " + ex.Message;
            MessageBox.Show(ex.Message, "Lỗi khi chạy forensics", MessageBoxButton.OK, MessageBoxImage.Error);
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

    private bool CanExportReport() => !IsRunning && HasResults && _lastResult is not null;

    /// <summary>
    /// Xuất báo cáo tiếng Việt (PDF/DOCX/HTML/JSON) cho phiên phân tích log vừa chạy.
    /// Đi qua cùng pipeline với "Run full audit" (ReportMetadataDialog → BuildData →
    /// WriteAllAsync) nhưng aggregator chỉ chứa findings của module "log-forensics"
    /// — do đó báo cáo tập trung hoàn toàn vào các nghi vấn phân tích nhật ký.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanExportReport))]
    private async Task ExportReportAsync()
    {
        if (_lastResult is null) { return; }

        // Bước 1 — mở dialog metadata để người dùng điền đơn vị/đoàn thanh tra
        // (giá trị lần trước được load sẵn).
        var currentSettings = _settingsStore.Load();
        var dialog = new ReportMetadataDialog(currentSettings)
        {
            Owner = Application.Current?.MainWindow
        };
        if (dialog.ShowDialog() != true || !dialog.ViewModel.Confirmed)
        {
            Status = "Đã huỷ xuất báo cáo.";
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

        // Bước 2 — folder picker. Mặc định gợi ý thư mục evidence của chính phiên
        // này để báo cáo nằm chung với bằng chứng — tiện cho hồ sơ thanh tra.
        var picker = new OpenFolderDialog
        {
            Title = "Chọn thư mục lưu báo cáo phân tích log"
        };
        if (!string.IsNullOrWhiteSpace(EvidenceRoot) && Directory.Exists(EvidenceRoot))
        {
            picker.InitialDirectory = EvidenceRoot;
        }
        if (picker.ShowDialog() != true) { return; }
        var folder = picker.FolderName;

        try
        {
            Status = "Đang xuất báo cáo…";

            // Dựng FindingsAggregator chỉ chứa module log-forensics — writer
            // render section "Kết quả theo module" sẽ hiển thị đúng nhóm này.
            var aggregator = new FindingsAggregator();
            aggregator.Add(new ModuleResult
            {
                ModuleId = "log-forensics",
                StartedAt = DateTimeOffset.Now,
                CompletedAt = DateTimeOffset.Now,
                Succeeded = true,
                Findings = _lastResult.Findings.Cast<object>().ToList()
            });

            var score = _scorer.Score(_lastResult.Findings);

            // Không có SystemInventory ở đây (module log-forensics không cần
            // quét WMI hardware); helper Build(null) tự điền placeholder.
            var device = DashboardHelpers.Build(null);

            var data = _reports.BuildData(
                aggregator,
                score,
                Environment.MachineName,
                device,
                Array.Empty<AppliedAction>(),
                metadata);

            var written = await Task.Run(
                () => _reports.WriteAllAsync(data, folder, CancellationToken.None)).ConfigureAwait(true);

            Status = $"Đã xuất {written.Count} báo cáo vào {folder}";
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = folder,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Could not open folder {Folder} in Explorer", folder);
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Log forensics report export failed");
            Status = $"Lỗi xuất báo cáo: {ex.Message}";
            MessageBox.Show(ex.Message, "SecAudit — Xuất báo cáo", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private void OpenEvidenceFolder()
    {
        if (string.IsNullOrEmpty(EvidenceRoot) || !Directory.Exists(EvidenceRoot)) { return; }
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
            _log.LogWarning(ex, "Open evidence folder failed");
        }
    }
}

public sealed record LogForensicsFindingRow(string Title, string Severity, string Category, string Asset, string Evidence);
public sealed record LogForensicsEvidenceRow(string Name, string OriginalPath, long SizeBytes, string Sha256);
