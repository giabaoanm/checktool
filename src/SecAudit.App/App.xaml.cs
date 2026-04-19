using System.Runtime.Versioning;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecAudit.App.Bootstrap;
using SecAudit.App.Views.Shell;
using SecAudit.Security;
using Serilog;

namespace SecAudit.App;

[SupportedOSPlatform("windows")]
public partial class App : Application
{
    private IHost? _host;

    public IServiceProvider Services
        => _host?.Services ?? throw new InvalidOperationException("Host not started.");

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Manifest forces admin; this is a belt-and-braces check for stripped manifests.
        if (!ElevationGuard.IsElevated())
        {
            if (ElevationGuard.TryRelaunchAsAdmin())
            {
                Shutdown();
                return;
            }
            MessageBox.Show(
                "SecAudit requires administrator privileges.",
                "SecAudit",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        _host = HostBuilderFactory.Build();
        await _host.StartAsync().ConfigureAwait(true);

        var main = _host.Services.GetRequiredService<MainWindow>();
        MainWindow = main;
        main.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            await _host.StopAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(true);
            _host.Dispose();
        }
        Log.CloseAndFlush();
        base.OnExit(e);
    }
}
