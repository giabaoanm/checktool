using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.App.ViewModels;

/// <summary>
/// UI wrapper around <see cref="Finding"/> that adds remediation state.
///
/// One instance per row in the dashboard DataGrid. Created by
/// <see cref="DashboardViewModel"/> after each module run; the wrapper resolves
/// its own remediation action up-front so the "Vá ngay" button binding is stable.
/// </summary>
public sealed partial class FindingViewModel : ObservableObject
{
    public Finding Finding { get; }
    private readonly IRemediationAction? _action;
    private readonly Action<FindingViewModel> _onApplied;
    private readonly FindingTriage _triage;

    /// <param name="onApplied">Callback the parent VM uses to record applied actions for reporting.</param>
    public FindingViewModel(
        Finding finding,
        IRemediationAction? action,
        Action<FindingViewModel> onApplied)
    {
        Finding = finding;
        _action = action;
        _onApplied = onApplied;
        _triage = FindingTriageInterpreter.Interpret(finding);
    }

    public Severity Severity => Finding.Severity;
    public string Category => Finding.Category;
    public string Title => Finding.Title;
    public string Evidence => Finding.Evidence;
    public string Asset => Finding.Asset;
    public string FindingId => Finding.Id;
    public string ActionGroup => _triage.ActionGroup;
    public string Confidence => _triage.Confidence;
    public string Scenario => _triage.Scenario;
    public string PlainExplanation => _triage.Explanation;
    public string OperatorSteps => _triage.StepsText;
    public string OperatorStepsPreview => _triage.Steps.Count == 0 ? string.Empty : _triage.Steps[0];
    public string OperatorGuidance => string.IsNullOrWhiteSpace(OperatorSteps)
        ? PlainExplanation
        : PlainExplanation + Environment.NewLine + Environment.NewLine + "Quy trình xử lý:" + Environment.NewLine + OperatorSteps;

    /// <summary>True when an <see cref="IRemediationAction"/> exists AND has not yet succeeded.</summary>
    public bool CanFix => _action is not null && RemediationStatus != AppliedStatus.Succeeded;

    /// <summary>The action descriptor (null when nothing is registered for this finding).</summary>
    public IRemediationAction? Action => _action;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanFix))]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    [NotifyCanExecuteChangedFor(nameof(ApplyFixCommand))]
    private AppliedStatus _remediationStatus = AppliedStatus.NotApplied;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private string _remediationMessage = string.Empty;

    /// <summary>Text shown inside the action cell when no button is rendered.</summary>
    public string StatusText => RemediationStatus switch
    {
        AppliedStatus.NotApplied => _action is null ? "Hướng dẫn thủ công" : string.Empty,
        AppliedStatus.Applying => "Đang vá…",
        AppliedStatus.Succeeded => string.IsNullOrEmpty(RemediationMessage)
            ? "✓ Đã vá"
            : "✓ " + RemediationMessage,
        AppliedStatus.Failed => "✗ " + RemediationMessage,
        _ => string.Empty
    };

    private bool CanApply()
        => _action is not null
           && RemediationStatus is AppliedStatus.NotApplied or AppliedStatus.Failed;

    [RelayCommand(CanExecute = nameof(CanApply))]
    private async Task ApplyFixAsync()
    {
        if (_action is null)
        {
            return;
        }

        if (_action.RequiresReboot)
        {
            var confirm = MessageBox.Show(
                $"{_action.Title}\n\n{_action.Description}\n\n" +
                "Hành động này YÊU CẦU khởi động lại máy để có hiệu lực. Tiếp tục?",
                "Xác nhận vá",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }
        }
        else
        {
            var confirm = MessageBox.Show(
                $"{_action.Title}\n\n{_action.Description}\n\nÁp dụng ngay?",
                "Xác nhận vá",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }
        }

        RemediationStatus = AppliedStatus.Applying;
        RemediationMessage = string.Empty;
        try
        {
            var result = await Task.Run(() => _action.ApplyAsync(CancellationToken.None))
                .ConfigureAwait(true);
            RemediationMessage = result.Message;
            RemediationStatus = result.Succeeded
                ? AppliedStatus.Succeeded
                : AppliedStatus.Failed;
        }
        catch (Exception ex)
        {
            RemediationMessage = ex.Message;
            RemediationStatus = AppliedStatus.Failed;
        }

        _onApplied(this);
    }
}

public enum AppliedStatus
{
    NotApplied,
    Applying,
    Succeeded,
    Failed
}
