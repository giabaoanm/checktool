using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Services;
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
    private readonly ILogger<LogForensicsViewModel> _log;
    private CancellationTokenSource? _cts;

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
    }

    public LogForensicsViewModel(
        LogForensicsEngine engine,
        EulaGate eula,
        ILogger<LogForensicsViewModel> log)
    {
        _engine = engine;
        _eula = eula;
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

    // Run state
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _status = "Sẵn sàng. Vui lòng chọn nguồn log.";
    [ObservableProperty] private int _filesProcessed;
    [ObservableProperty] private long _recordsProcessed;
    [ObservableProperty] private string? _evidenceRoot;
    [ObservableProperty] private string? _sessionId;

    [RelayCommand]
    private void BrowseLocalPath()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn tệp log (hoặc Cancel để chọn thư mục)",
            Filter = "Log files|*.log;*.evtx;*.txt;*.out;*.syslog;*.access;*.error|All|*.*",
            CheckFileExists = false,
            CheckPathExists = true,
            Multiselect = false
        };
        if (dlg.ShowDialog() == true)
        {
            LocalPath = dlg.FileName;
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
            + "(Luật An ninh mạng 2018 Điều 8 và BLHS Điều 289)",
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
            InternalCidrs = InternalCidrs
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
            Status = $"Xong. {result.TotalFiles} tệp, {result.TotalRecords} bản ghi, {result.Findings.Count} phát hiện.";
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
