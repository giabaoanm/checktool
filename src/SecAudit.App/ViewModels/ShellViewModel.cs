using CommunityToolkit.Mvvm.ComponentModel;

namespace SecAudit.App.ViewModels;

public sealed partial class ShellViewModel : ObservableObject
{
    [ObservableProperty]
    private string _applicationTitle = "SecAudit";
}
