using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Modules.DeviceForensics;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Modules.MalwareInspector;
using SecAudit.Modules.MalwareInspector.Iocs;
using SecAudit.Modules.MalwareInspector.Models;
using SecAudit.Modules.PatchCve;
using SecAudit.Modules.RemoteAccess;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;
using SecAudit.App.Services;
using SecAudit.App.Views.Dialogs;
using SecAudit.Reporting;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.App.ViewModels;

public sealed partial class DashboardViewModel : ObservableObject
{
    private static readonly char[] WhitespaceChars = { ' ', '\t' };

    private readonly IEnumerable<IAuditModule> _modules;
    private readonly RiskScoreCalculator _scorer;
    private readonly ReportService _reports;
    private readonly RemediationRegistry _remediations;
    private readonly IncidentResponseActionFactory _incidentActions;
    private readonly ReportSettingsStore _settingsStore;
    private readonly IocExporter _iocExporter;
    private readonly MutableOfflineTarget _offlineTarget;
    private readonly ILogger<DashboardViewModel> _logger;
    private FindingsAggregator? _lastAggregator;
    private RiskScore _lastScore;
    private SystemInventory? _lastInventory;
    private PatchSnapshot? _lastPatchSnapshot;
    private RemoteAccessSnapshot? _lastRemoteAccessSnapshot;
    private ForensicsResult? _lastForensicsResult;
    private MalwareInspectorSnapshot? _lastMalwareSnapshot;
    /// <summary>Snapshot of remediation outcomes since the last full audit run.</summary>
    private readonly List<AppliedAction> _appliedActions = new();

    public DashboardViewModel(
        IEnumerable<IAuditModule> modules,
        RiskScoreCalculator scorer,
        ReportService reports,
        RemediationRegistry remediations,
        IncidentResponseActionFactory incidentActions,
        ReportSettingsStore settingsStore,
        IocExporter iocExporter,
        MutableOfflineTarget offlineTarget,
        ILogger<DashboardViewModel> logger)
    {
        _modules = modules;
        _scorer = scorer;
        _reports = reports;
        _remediations = remediations;
        _incidentActions = incidentActions;
        _settingsStore = settingsStore;
        _iocExporter = iocExporter;
        _offlineTarget = offlineTarget;
        _logger = logger;

        RefreshAvailableVolumes();
    }

    /// <summary>
    /// Audit target selection — drives whether the next audit run scans the live OS or
    /// a Windows volume mounted at <see cref="OfflineRoot"/>.
    /// </summary>
    public enum TargetMode { Live, OfflineDrive }
    public enum PolicyProfile { StrictIntranet, InternetAllowed }

    [ObservableProperty]
    private TargetMode _selectedMode = TargetMode.Live;

    [ObservableProperty]
    private PolicyProfile _selectedPolicyProfile = PolicyProfile.StrictIntranet;

    public bool IsLiveMode
    {
        get => SelectedMode == TargetMode.Live;
        set { if (value) { SelectedMode = TargetMode.Live; OnPropertyChanged(nameof(IsLiveMode)); OnPropertyChanged(nameof(IsOfflineMode)); } }
    }

    public bool IsOfflineMode
    {
        get => SelectedMode == TargetMode.OfflineDrive;
        set { if (value) { SelectedMode = TargetMode.OfflineDrive; OnPropertyChanged(nameof(IsLiveMode)); OnPropertyChanged(nameof(IsOfflineMode)); } }
    }

    public bool IsStrictIntranetPolicy
    {
        get => SelectedPolicyProfile == PolicyProfile.StrictIntranet;
        set { if (value) { SelectedPolicyProfile = PolicyProfile.StrictIntranet; OnPropertyChanged(nameof(IsStrictIntranetPolicy)); OnPropertyChanged(nameof(IsInternetAllowedPolicy)); } }
    }

    public bool IsInternetAllowedPolicy
    {
        get => SelectedPolicyProfile == PolicyProfile.InternetAllowed;
        set { if (value) { SelectedPolicyProfile = PolicyProfile.InternetAllowed; OnPropertyChanged(nameof(IsStrictIntranetPolicy)); OnPropertyChanged(nameof(IsInternetAllowedPolicy)); } }
    }

    [ObservableProperty]
    private string? _offlineRoot;

    /// <summary>List of mounted volumes the operator can pick for offline audit, with
    /// a marker indicating which look like Windows installs.</summary>
    public ObservableCollection<string> AvailableVolumes { get; } = new();

    [RelayCommand]
    private void RefreshAvailableVolumes()
    {
        AvailableVolumes.Clear();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (!d.IsReady) { continue; }
                if (d.DriveType is not (DriveType.Fixed or DriveType.Removable)) { continue; }
                var root = d.RootDirectory.FullName;
                bool isWin = File.Exists(Path.Combine(root, "Windows", "System32", "config", "SYSTEM"));
                var marker = isWin ? "  *Windows install*" : "";
                AvailableVolumes.Add($"{root}    {d.VolumeLabel}  ({d.DriveType}, {d.TotalSize / 1_000_000_000} GB){marker}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Volume enumeration failed");
        }
    }

    public ObservableCollection<FindingViewModel> Findings { get; } = new();

    /// <summary>Read-only snapshot for the report writer.</summary>
    public IReadOnlyList<AppliedAction> AppliedActions => _appliedActions;

    [ObservableProperty]
    private int _overallScore = 100;

    [ObservableProperty]
    private string _overallBand = "Excellent";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportReportsCommand))]
    private bool _isRunning;

    [ObservableProperty]
    private string _status = "Ready";

    [ObservableProperty]
    private int _progressPercent;

    [RelayCommand]
    private async Task RunFullAuditAsync()
    {
        if (IsRunning)
        {
            return;
        }

        // Switch the offline-target wrapper based on user pick. Live keeps the default;
        // OfflineDrive instantiates MountedVolumeOfflineTarget which loads the volume's
        // SOFTWARE / SYSTEM hives. We always reset to live in the finally block so
        // hives are unmounted before the user explores the rest of the GUI.
        if (SelectedMode == TargetMode.OfflineDrive)
        {
            var rawRoot = (OfflineRoot ?? string.Empty).Trim();
            // Operator may have selected the dropdown row "C:\    Local Disk (Fixed, 480 GB)".
            // Extract just the path token before the first whitespace.
            var spaceIdx = rawRoot.IndexOfAny(WhitespaceChars);
            if (spaceIdx > 0) { rawRoot = rawRoot[..spaceIdx]; }
            if (string.IsNullOrWhiteSpace(rawRoot))
            {
                MessageBox.Show("Vui lòng chọn ổ đĩa muốn audit từ danh sách.",
                    "SecAudit — Chọn ổ đĩa", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            try
            {
                var mounted = new MountedVolumeOfflineTarget(rawRoot);
                _offlineTarget.Switch(mounted);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Không mount được ổ '{rawRoot}': {ex.Message}\n\nChắc chắn ổ này có \\Windows\\System32\\config\\SYSTEM "
                    + "và bạn đang chạy SecAudit dưới quyền Administrator.",
                    "SecAudit — Lỗi mount", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }
        else
        {
            // Make sure any previously-mounted offline target is released and we are back to live.
            _offlineTarget.ResetToLive();
        }

        IsRunning = true;
        Status = "Running…";
        ProgressPercent = 0;
        Findings.Clear();
        _appliedActions.Clear();

        var progress = new Progress<ProgressUpdate>(u =>
        {
            ProgressPercent = u.PercentComplete;
            Status = $"[{u.ModuleId}] {u.Stage} — {u.Message}";
        });

        // Auto-configure log-forensics to scan the chosen target's event-log directory.
        // Live mode → the running OS's %WINDIR%\System32\winevt\Logs.
        // Offline mode → <selected volume>\Windows\System32\winevt\Logs (mounted volume).
        // Without this the module no-op'd silently during the dashboard full audit —
        // operator at Sơn La (2026-04-27) wanted log evidence in section 8 by default.
        var auditOptions = new Dictionary<string, string>(StringComparer.Ordinal);
        auditOptions[DeviceForensicsModule.OptionPolicyProfileKey] =
            SelectedPolicyProfile == PolicyProfile.InternetAllowed
                ? DeviceForensicsModule.PolicyInternetAllowed
                : DeviceForensicsModule.PolicyStrictIntranet;
        try
        {
            var logDir = Path.Combine(_offlineTarget.WindowsDirectory, "System32", "winevt", "Logs");
            if (Directory.Exists(logDir))
            {
                var settings = new SecAudit.Modules.LogForensics.Models.ForensicsSettings
                {
                    SourceKind = SecAudit.Modules.LogForensics.Models.ForensicsSourceKind.LocalFolder,
                    LocalPath = logDir,
                    LocalRecursive = false
                };
                auditOptions[SecAudit.Modules.LogForensics.LogForensicsModule.OptionKey] =
                    System.Text.Json.JsonSerializer.Serialize(settings);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to auto-configure log-forensics");
        }

        var context = new ScanContext
        {
            MachineName = Environment.MachineName,
            CurrentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown",
            StartedAt = DateTimeOffset.UtcNow,
            Options = auditOptions
        };

        var aggregator = new FindingsAggregator();
        try
        {
            foreach (var module in _modules)
            {
                _logger.LogInformation("Running module {ModuleId}", module.Metadata.Id);
                // Offload to background thread so WMI/Registry/file I/O doesn't freeze the UI.
                // Progress<T> captured on the UI thread will marshal callbacks back automatically.
                var capturedModule = module;
                var result = await Task.Run(
                    () => capturedModule.RunAsync(context, progress, CancellationToken.None)).ConfigureAwait(true);
                aggregator.Add(result);
                foreach (var raw in result.Findings)
                {
                    if (raw is Finding f)
                    {
                        var action = _remediations.TryGet(f.Id)
                            ?? _incidentActions.TryCreate(f);
                        Findings.Add(new FindingViewModel(f, action, OnRemediationApplied));
                    }
                }
                if (!result.Succeeded)
                {
                    _logger.LogWarning("Module {ModuleId} failed: {Reason}", module.Metadata.Id, result.FailureReason);
                }
            }

            var score = _scorer.Score(Findings.Select(vm => vm.Finding));
            OverallScore = score.Value;
            OverallBand = score.Band;
            Status = $"Completed — {Findings.Count} finding(s)";
            ProgressPercent = 100;
            _lastAggregator = aggregator;
            _lastScore = score;
            _lastInventory = context.GetShared<SystemInventory>(SystemInfoModule.SharedInventoryKey);
            // Pull cross-module snapshots so the export step can render the new
            // baseline sections (License, Patch, Scope) regardless of whether
            // any finding fired.
            _lastPatchSnapshot = context.GetShared<PatchSnapshot>(PatchCveModule.SharedSnapshotKey);
            _lastRemoteAccessSnapshot = context.GetShared<RemoteAccessSnapshot>(RemoteAccessModule.SharedSnapshotKey);
            _lastForensicsResult = context.GetShared<ForensicsResult>("log-forensics.result");
            _lastMalwareSnapshot = context.GetShared<MalwareInspectorSnapshot>(MalwareInspectorModule.SharedSnapshotKey);
            ExportReportsCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Audit run failed");
            Status = $"Error: {ex.Message}";
            MessageBox.Show(ex.Message, "SecAudit", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsRunning = false;
            // Always release any mounted offline volume after the audit ends. Hives stay
            // loaded under HKLM otherwise — confusing if operator opens regedit afterwards.
            // Live mode just no-ops since LiveOfflineTarget has no resources to release.
            if (SelectedMode == TargetMode.OfflineDrive)
            {
                _offlineTarget.ResetToLive();
            }
        }
    }

    private void OnRemediationApplied(FindingViewModel vm)
    {
        if (vm.Action is null)
        {
            return;
        }
        _appliedActions.Add(new AppliedAction(
            FindingId: vm.FindingId,
            ActionTitle: vm.Action.Title,
            Succeeded: vm.RemediationStatus == AppliedStatus.Succeeded,
            Message: vm.RemediationMessage,
            RebootRequired: vm.Action.RequiresReboot && vm.RemediationStatus == AppliedStatus.Succeeded,
            AppliedAt: DateTimeOffset.UtcNow));
        _logger.LogInformation(
            "Remediation {Action} for {Finding}: {Status} — {Message}",
            vm.Action.Title, vm.FindingId, vm.RemediationStatus, vm.RemediationMessage);
    }

    private bool CanExportReports() => !IsRunning && _lastAggregator is not null;

    [RelayCommand(CanExecute = nameof(CanExportReports))]
    private async Task ExportReportsAsync()
    {
        if (_lastAggregator is null)
        {
            return;
        }

        // Step 1 — metadata popup. Giá trị lần trước được load sẵn, user chỉnh rồi
        // "Xuất báo cáo". Nhấn Hủy ở đây abort luôn cả folder picker.
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
            // Persist failure shouldn't block the current export — user still gets the
            // report, just loses the "remember next time" convenience.
            _logger.LogWarning(ex, "Failed to persist report metadata; continuing export anyway");
        }

        // Step 2 — folder picker.
        var picker = new OpenFolderDialog
        {
            Title = "Chọn thư mục lưu báo cáo SecAudit"
        };
        if (picker.ShowDialog() != true)
        {
            return;
        }
        var folder = picker.FolderName;

        try
        {
            Status = "Đang xuất báo cáo…";
            var device = ReportSectionBuilder.BuildDeviceProfile(_lastInventory);
            var license = ReportSectionBuilder.BuildLicenseSummary(_lastInventory);
            var patch = ReportSectionBuilder.BuildPatchSummary(_lastPatchSnapshot);
            var scope = ReportSectionBuilder.BuildScanScope(_lastRemoteAccessSnapshot, _lastForensicsResult);
            var data = _reports.BuildData(
                _lastAggregator,
                _lastScore,
                Environment.MachineName,
                device,
                _appliedActions.ToList(),
                metadata,
                license: license,
                patch: patch,
                scope: scope);
            var written = await Task.Run(
                () => _reports.WriteAllAsync(data, folder, CancellationToken.None)).ConfigureAwait(true);

            // IOC hand-off bundle (txt/csv/regkeys) for Kaspersky / regedit triage. Same
            // file-prefix pattern as ReportService so artifacts collate together. Only emit
            // when MalwareInspector ran and produced at least one analysed candidate.
            int iocCount = 0;
            if (_lastMalwareSnapshot is not null && _lastMalwareSnapshot.IocEntries.Count > 0)
            {
                var stamp = data.GeneratedAt.ToString("yyyyMMdd-HHmmss");
                var prefix = $"secaudit-{Environment.MachineName}-{stamp}";
                var iocResult = await Task.Run(
                    () => _iocExporter.Export(_lastMalwareSnapshot.IocEntries, folder, prefix)).ConfigureAwait(true);
                iocCount = iocResult.WrittenPaths.Count;
                foreach (var err in iocResult.Errors)
                {
                    _logger.LogWarning("IOC export warning: {Error}", err);
                }
            }

            Status = iocCount > 0
                ? $"Đã xuất {written.Count} báo cáo + {iocCount} file IOC vào {folder}"
                : $"Đã xuất {written.Count} báo cáo vào {folder}";
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
                _logger.LogWarning(ex, "Could not open folder {Folder} in Explorer", folder);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Report export failed");
            Status = $"Export error: {ex.Message}";
            MessageBox.Show(ex.Message, "SecAudit", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}

// Helpers
internal static class DashboardHelpers
{
    /// <summary>
    /// Backwards-compatible thin wrapper around <see cref="ReportSectionBuilder.BuildDeviceProfile"/>.
    /// The richer builder is preferred for new code (it also exposes License/Patch/Scope sections);
    /// kept only because <c>LogForensicsViewModel</c> still calls this signature for its
    /// forensics-only export path.
    /// </summary>
    public static DeviceProfile Build(SystemInventory? inv)
        => ReportSectionBuilder.BuildDeviceProfile(inv);
}
