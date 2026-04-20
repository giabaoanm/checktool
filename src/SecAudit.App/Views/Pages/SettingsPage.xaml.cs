using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Controls;
using SecAudit.App.ViewModels;
using SecAudit.App.Views.Dialogs;
using SecAudit.Security;

namespace SecAudit.App.Views.Pages;

[SupportedOSPlatform("windows")]
public partial class SettingsPage : Page
{
    private readonly SettingsViewModel _viewModel;
    private readonly EulaGate _eulaGate;

    public SettingsPage(SettingsViewModel viewModel, EulaGate eulaGate)
    {
        _viewModel = viewModel;
        _eulaGate = eulaGate;
        InitializeComponent();
        DataContext = viewModel;
    }

    /// <summary>
    /// Xem lại / xác nhận lại thoả thuận uỷ quyền. Đã được chấp nhận trước đó,
    /// nhưng user có thể muốn đọc lại hoặc xác nhận lại (ghi đè marker với
    /// timestamp mới) — ví dụ khi bàn giao máy, khi chuyển ca trực.
    /// </summary>
    private void OnReviewEulaClick(object sender, RoutedEventArgs e)
    {
        var dialog = new EulaDialog(_eulaGate)
        {
            Owner = Window.GetWindow(this),
        };
        dialog.ShowDialog();
        // Đồng ý lại → marker refreshed; huỷ → không làm gì (app vẫn chạy bình thường).
        _viewModel.RefreshEulaStatus();
    }
}
