using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.App.ViewModels;

public sealed partial class DashboardViewModel : ObservableObject
{
    private readonly IEnumerable<IAuditModule> _modules;
    private readonly RiskScoreCalculator _scorer;
    private readonly ILogger<DashboardViewModel> _logger;

    public DashboardViewModel(
        IEnumerable<IAuditModule> modules,
        RiskScoreCalculator scorer,
        ILogger<DashboardViewModel> logger)
    {
        _modules = modules;
        _scorer = scorer;
        _logger = logger;
    }

    public ObservableCollection<Finding> Findings { get; } = new();

    [ObservableProperty]
    private int _overallScore = 100;

    [ObservableProperty]
    private string _overallBand = "Excellent";

    [ObservableProperty]
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
                foreach (var raw in result.Findings)
                {
                    if (raw is Finding f)
                    {
                        Findings.Add(f);
                    }
                }
                if (!result.Succeeded)
                {
                    _logger.LogWarning("Module {ModuleId} failed: {Reason}", module.Metadata.Id, result.FailureReason);
                }
            }

            var score = _scorer.Score(Findings);
            OverallScore = score.Value;
            OverallBand = score.Band;
            Status = $"Completed — {Findings.Count} finding(s)";
            ProgressPercent = 100;
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
}
