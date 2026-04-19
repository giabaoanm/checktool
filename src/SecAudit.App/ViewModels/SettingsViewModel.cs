using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using SecAudit.Security;

namespace SecAudit.App.ViewModels;

[SupportedOSPlatform("windows")]
public sealed partial class SettingsViewModel : ObservableObject
{
    [ObservableProperty]
    private string _appVersion = typeof(SettingsViewModel).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    [ObservableProperty]
    private string _culture = System.Globalization.CultureInfo.CurrentUICulture.Name;

    [ObservableProperty]
    private string _theme = "Dark";

    [ObservableProperty]
    private bool _isElevated = ElevationGuard.IsElevated();
}
