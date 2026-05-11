using System.Runtime.Versioning;
using System.Windows.Controls;
using SecAudit.App.ViewModels;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class WindowsIrPage : Page
{
    public WindowsIrPage(WindowsIrViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
