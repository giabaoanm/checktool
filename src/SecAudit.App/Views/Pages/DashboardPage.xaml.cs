using System.Runtime.Versioning;
using System.Windows.Controls;
using SecAudit.App.ViewModels;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class DashboardPage : Page
{
    public DashboardPage(DashboardViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
