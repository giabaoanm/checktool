using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Modules.MalwareInspector;
using SecAudit.Modules.MalwareInspector.Iocs;
using SecAudit.Modules.MalwareInspector.Models;
using SecAudit.Modules.PatchCve;
using SecAudit.Modules.RemoteAccess;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;
using SecAudit.App.Views.Dialogs;
using SecAudit.Reporting;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.App.ViewModels;

public sealed partial class DashboardViewModel : ObservableObject
{
    private readonly IEnumerable<IAuditModule> _modules;
    private readonly RiskScoreCalculator _scorer;
    private readonly ReportService _reports;
    private readonly RemediationRegistry _remediations;
    private readonly ReportSettingsStore _settingsStore;
    private readonly IocExporter _iocExporter;
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
        ReportSettingsStore settingsStore,
        IocExporter iocExporter,
        ILogger<DashboardViewModel> logger)
    {
        _modules = modules;
        _scorer = scorer;
        _reports = reports;
        _remediations = remediations;
        _settingsStore = settingsStore;
        _iocExporter = iocExporter;
        _logger = logger;
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

        var context = new ScanContext
        {
            MachineName = Environment.MachineName,
            CurrentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown",
            StartedAt = DateTimeOffset.UtcNow,
            Options = new Dictionary<string, string>()
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
                        var action = _remediations.TryGet(f.Id);
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
