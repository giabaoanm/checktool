using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using SecAudit.Security;
using Wpf.Ui.Controls;

namespace SecAudit.App.Views.Dialogs;

/// <summary>
/// Modal EULA / uỷ quyền kiểm tra. Hiển thị LẦN ĐẦU khi user chạy SecAudit,
/// hoặc bất cứ khi nào <see cref="EulaGate.IsAccepted"/> trả về false.
/// Yêu cầu user:
///   1. Tick checkbox "Tôi được uỷ quyền"
///   2. Tick checkbox "Tôi hiểu audit log"
///   3. Gõ chuỗi "TÔI ĐƯỢC ỦY QUYỀN" (hoặc biến thể "UỶ" cổ điển)
/// Khi đủ 3 điều kiện, nút "Đồng ý &amp; tiếp tục" được bật. Bấm → ghi marker
/// xuống <c>%LOCALAPPDATA%\SecAudit\eula-accepted.marker</c> kèm SID + timestamp.
/// Bấm "Huỷ" hoặc đóng cửa sổ → shell tự shutdown (không được quyền scan).
/// </summary>
[SupportedOSPlatform("windows")]
public partial class EulaDialog : FluentWindow
{
    // Tiếng Việt có 2 cách bỏ dấu cho cụm "uỷ/ủy":
    //   - Cổ điển (pre-1980s, sách cũ): "UỶ" — dấu hỏi trên Y
    //   - Hiện đại (chuẩn GD&ĐT hiện nay): "ỦY" — dấu hỏi trên U
    // Cả 2 đều hợp lệ → accept cả 2 để user không bị chặn vì bộ gõ Unikey
    // thường mặc định ra kiểu hiện đại "ỦY".
    private static readonly string[] AcceptedPhrases =
    {
        "TÔI ĐƯỢC ỦY QUYỀN",
        "TÔI ĐƯỢC UỶ QUYỀN"
    };
    private const string DisplayPhrase = "TÔI ĐƯỢC ỦY QUYỀN";

    private readonly EulaGate _gate;

    /// <summary>Kết quả sau khi dialog đóng. true = user xác nhận đồng ý.</summary>
    public bool Accepted { get; private set; }

    public EulaDialog(EulaGate gate)
    {
        _gate = gate;
        InitializeComponent();
    }

    private void OnAnyInputChanged(object? sender, RoutedEventArgs e)
        => RecomputeAcceptButton();

    private void OnAnyInputChanged(object? sender, TextChangedEventArgs e)
        => RecomputeAcceptButton();

    private void RecomputeAcceptButton()
    {
        bool authorizedTicked = AgreeAuthorizedCheck.IsChecked == true;
        bool loggingTicked = AgreeLoggingCheck.IsChecked == true;
        bool typedMatches = IsPhraseAccepted(ConfirmTypedBox.Text);

        AcceptButton.IsEnabled = authorizedTicked && loggingTicked && typedMatches;

        // Cập nhật hint động cho user biết còn thiếu gì.
        string hint;
        if (!authorizedTicked || !loggingTicked)
        {
            hint = "Cần tích cả 2 ô xác nhận.";
        }
        else if (!typedMatches)
        {
            hint = $"Gõ chính xác: {DisplayPhrase} (hoặc TÔI ĐƯỢC UỶ QUYỀN).";
        }
        else
        {
            hint = "Đã đủ điều kiện — bấm \"Đồng ý & tiếp tục\".";
        }
        ValidationHint.Text = hint;
    }

    /// <summary>
    /// Trả về true nếu <paramref name="input"/> khớp với một trong các chuỗi
    /// xác nhận hợp lệ, sau khi:
    ///   - Normalize Unicode NFC (Unikey có thể sinh tổ hợp ký tự decomposed).
    ///   - Loại bỏ khoảng trắng đầu/cuối.
    ///   - So sánh case-insensitive (tránh user vô tình gõ thường).
    ///   - Accept cả 2 cách viết "UỶ" (cổ điển) và "ỦY" (hiện đại).
    /// </summary>
    private static bool IsPhraseAccepted(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) { return false; }
        var normalized = input.Trim().Normalize(NormalizationForm.FormC);
        foreach (var phrase in AcceptedPhrases)
        {
            var target = phrase.Normalize(NormalizationForm.FormC);
            if (string.Equals(normalized, target, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private void OnAcceptClick(object sender, RoutedEventArgs e)
    {
        // Ghi marker xuống disk kèm SID để audit log có thể chứng minh
        // user nào đã đồng ý trên máy nào vào thời điểm nào.
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? "unknown";
        _gate.RecordAcceptance(sid);
        Accepted = true;
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        Accepted = false;
        DialogResult = false;
        Close();
    }
}
