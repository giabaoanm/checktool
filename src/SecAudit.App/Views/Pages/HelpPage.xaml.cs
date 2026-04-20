using System.Runtime.Versioning;
using System.Windows.Controls;
using System.Windows.Input;

namespace SecAudit.App.Views.Pages;

/// <summary>
/// Trang "Hướng dẫn sử dụng" — nội dung tĩnh (không cần ViewModel), mô tả
/// quy trình 5 bước, các module, quy cách biên bản, chế độ offline/WinPE
/// và FAQ cho quản trị viên SOC. Truy cập từ FooterMenuItems của NavigationView.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class HelpPage : Page
{
    public HelpPage()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Handler PreviewMouseWheel GẮN Ở CẤP PAGE (root).
    /// WPF tunnel event: Page (root) → ScrollViewer → StackPanel → Card.
    /// Gắn ở Page đảm bảo handler chạy đầu tiên, trước khi WPF-UI Card
    /// kịp mark e.Handled=true (là nguyên nhân cuộn chuột bị chặn ở các
    /// version WPF-UI 3.x). Ta chủ động ScrollToVerticalOffset rồi đặt
    /// e.Handled=true để các handler con không xử lý lại gây giật.
    /// </summary>
    private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        // MainScroll là x:Name của ScrollViewer — luôn có sau InitializeComponent.
        if (MainScroll is null) { return; }

        // Delta âm = user cuộn xuống → muốn tăng VerticalOffset.
        // Mặc định WPF cuộn khoảng 48 pixel per notch; giữ nguyên hệ số để
        // cảm giác quen tay.
        MainScroll.ScrollToVerticalOffset(MainScroll.VerticalOffset - e.Delta);
        e.Handled = true;
    }
}
