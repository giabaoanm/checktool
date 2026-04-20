using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using SecAudit.Security;

namespace SecAudit.App.ViewModels;

/// <summary>
/// Settings page — hiển thị thông tin app + trạng thái thoả thuận EULA.
/// Phần biên bản kiểm tra (header, căn cứ, thành phần, chữ ký) được để trống
/// sẵn trong mẫu để người kiểm tra điền tay sau khi in, nên không cần cấu hình.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly EulaGate _eulaGate;

    [ObservableProperty]
    private string _appVersion = typeof(SettingsViewModel).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    [ObservableProperty]
    private string _culture = CultureInfo.CurrentUICulture.Name;

    [ObservableProperty]
    private string _theme = "Dark";

    [ObservableProperty]
    private bool _isElevated = ElevationGuard.IsElevated();

    [ObservableProperty]
    private string _eulaStatus = "(chưa xác định)";

    public SettingsViewModel(EulaGate eulaGate)
    {
        _eulaGate = eulaGate;
        RefreshEulaStatus();
    }

    /// <summary>Đọc marker EULA và format lại trạng thái hiển thị.</summary>
    public void RefreshEulaStatus()
    {
        var markerPath = Path.Combine(_eulaGate.AcceptanceFolder, "eula-accepted.marker");
        if (!File.Exists(markerPath))
        {
            EulaStatus = "Chưa xác nhận";
            return;
        }
        try
        {
            var content = File.ReadAllText(markerPath).Trim();
            // Format marker: "{DateTimeOffset:O}\t{userSid}\t{MachineName}"
            var parts = content.Split('\t');
            if (parts.Length >= 1
                && DateTimeOffset.TryParse(parts[0], CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var when))
            {
                EulaStatus = "Đã xác nhận lúc "
                    + when.LocalDateTime.ToString("HH:mm dd/MM/yyyy", CultureInfo.InvariantCulture);
            }
            else
            {
                EulaStatus = "Đã xác nhận";
            }
        }
        catch
        {
            // Nếu marker hỏng, coi như đã accept (EulaGate.IsAccepted chỉ check File.Exists)
            // nhưng không parse được thời điểm → hiển thị fallback.
            EulaStatus = "Đã xác nhận";
        }
    }
}
