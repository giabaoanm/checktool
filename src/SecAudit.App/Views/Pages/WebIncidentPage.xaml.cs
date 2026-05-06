using System.Runtime.Versioning;
using System.Windows.Controls;
using SecAudit.App.ViewModels;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class WebIncidentPage : Page
{
    public WebIncidentPage(WebIncidentViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
