using System.Windows;
using SecAudit.App.ViewModels;
using SecAudit.Core.Services;
using Wpf.Ui.Controls;

namespace SecAudit.App.Views.Dialogs;

/// <summary>
/// Modal popup hiện trước khi xuất báo cáo. Cho phép admin điền sẵn thông tin
/// header/chữ ký để đỡ phải ghi tay sau khi in. Nếu bấm "Hủy" → trả về
/// <c>DialogResult = false</c>, DashboardViewModel sẽ abort export.
/// </summary>
public partial class ReportMetadataDialog : FluentWindow
{
    public ReportMetadataViewModel ViewModel { get; }

    public ReportMetadataDialog(ReportSettings initial)
    {
        ViewModel = new ReportMetadataViewModel();
        ViewModel.LoadFrom(initial);
        DataContext = ViewModel;
        InitializeComponent();
    }

    private void OnConfirmClick(object sender, RoutedEventArgs e)
    {
        ViewModel.Confirmed = true;
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        ViewModel.Confirmed = false;
        DialogResult = false;
        Close();
    }
}
