using System.Runtime.Versioning;
using System.Windows.Controls;
using SecAudit.App.ViewModels;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class SettingsPage : Page
{
    public SettingsPage(SettingsViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
