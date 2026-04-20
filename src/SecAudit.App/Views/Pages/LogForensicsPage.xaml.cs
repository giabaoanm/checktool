using System.Runtime.Versioning;
using System.Windows.Controls;
using SecAudit.App.ViewModels;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class LogForensicsPage : Page
{
    private readonly LogForensicsViewModel _vm;

    public LogForensicsPage(LogForensicsViewModel viewModel)
    {
        _vm = viewModel;
        InitializeComponent();
        DataContext = viewModel;
    }

    // PasswordBox.Password is intentionally not a dependency property, so we push
    // the value to the VM manually. The VM keeps the secret only for the duration
    // of a single run (it lives inside ForensicsSettings and is never persisted).
    private void SshPasswordBox_PasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.PasswordBox box)
        {
            _vm.SshPassword = string.IsNullOrEmpty(box.Password) ? null : box.Password;
        }
    }
}
