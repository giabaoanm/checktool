using System.Runtime.Versioning;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecAudit.App.Bootstrap;
using SecAudit.App.Views.Dialogs;
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

        // Make sure any unhandled exception lands in the log file instead of a silent exit.
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            Log.Fatal(args.ExceptionObject as Exception, "Unhandled AppDomain exception");
            Log.CloseAndFlush();
        };
        DispatcherUnhandledException += (_, args) =>
        {
            Log.Error(args.Exception, "Unhandled Dispatcher exception");
            MessageBox.Show(args.Exception.Message, "SecAudit — unhandled error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            Log.Error(args.Exception, "Unobserved task exception");
            args.SetObserved();
        };

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

        // EULA gate: nếu lần đầu chạy (chưa có marker) — hiển thị modal xác nhận
        // uỷ quyền trước khi cho phép mở shell. User bấm "Huỷ" hoặc đóng cửa sổ
        // không đồng ý → shutdown; không có quyền scan.
        var eulaGate = _host.Services.GetRequiredService<EulaGate>();
        if (!eulaGate.IsAccepted())
        {
            var eulaDialog = new EulaDialog(eulaGate);
            bool? result = eulaDialog.ShowDialog();
            if (result != true || !eulaDialog.Accepted)
            {
                Log.Information("EULA not accepted. Shutting down.");
                Shutdown(0);
                return;
            }
            Log.Information("EULA accepted and marker written.");
        }

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
