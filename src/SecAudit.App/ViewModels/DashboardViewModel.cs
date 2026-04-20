using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
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
    private readonly ILogger<DashboardViewModel> _logger;
    private FindingsAggregator? _lastAggregator;
    private RiskScore _lastScore;
    private SystemInventory? _lastInventory;
    /// <summary>Snapshot of remediation outcomes since the last full audit run.</summary>
    private readonly List<AppliedAction> _appliedActions = new();

    public DashboardViewModel(
        IEnumerable<IAuditModule> modules,
        RiskScoreCalculator scorer,
        ReportService reports,
        RemediationRegistry remediations,
        ReportSettingsStore settingsStore,
        ILogger<DashboardViewModel> logger)
    {
        _modules = modules;
        _scorer = scorer;
        _reports = reports;
        _remediations = remediations;
        _settingsStore = settingsStore;
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
            var device = DashboardHelpers.Build(_lastInventory);
            var data = _reports.BuildData(
                _lastAggregator,
                _lastScore,
                Environment.MachineName,
                device,
                _appliedActions.ToList(),
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
    /// Convert the System Info module's <see cref="SystemInventory"/> + a fresh NIC
    /// enumeration into the report's section-1 <see cref="DeviceProfile"/>.
    /// Falls back to "(unknown)" placeholders if the inventory is missing — happens
    /// only when the SystemInfo module errored mid-run.
    /// </summary>
    public static DeviceProfile Build(SystemInventory? inv)
    {
        var nics = NetworkAddressCollector.Collect();
        if (inv is null)
        {
            return new DeviceProfile(
                ComputerName: Environment.MachineName,
                Cpu: "(unknown)",
                BiosSerial: "(unknown)",
                TotalRam: "(unknown)",
                OperatingSystem: Environment.OSVersion.VersionString,
                NetworkAddresses: nics);
        }
        var ramGb = inv.Hardware.TotalPhysicalMemoryBytes / (1024.0 * 1024 * 1024);
        return new DeviceProfile(
            ComputerName: Environment.MachineName,
            Cpu: $"{inv.Hardware.CpuName} ({inv.Hardware.CpuCores}C/{inv.Hardware.CpuLogicalProcessors}T)",
            BiosSerial: string.IsNullOrWhiteSpace(inv.Hardware.SerialNumber) ? "(không có)" : inv.Hardware.SerialNumber,
            TotalRam: ramGb >= 0.5 ? $"{ramGb:0.0} GB" : "(unknown)",
            OperatingSystem: $"{inv.OperatingSystem.Caption} build {inv.OperatingSystem.BuildNumber} ({inv.OperatingSystem.DisplayVersion})",
            NetworkAddresses: nics);
    }
}
