using System.Runtime.Versioning;
using System.Windows.Controls;
using SecAudit.App.ViewModels;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class LinuxIncidentPage : Page
{
    public LinuxIncidentPage(LinuxIncidentViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
