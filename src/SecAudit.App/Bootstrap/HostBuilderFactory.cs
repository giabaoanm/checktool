using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecAudit.App.ViewModels;
using SecAudit.App.Views.Pages;
using SecAudit.App.Views.Shell;
using SecAudit.Core.Services;
using SecAudit.Infrastructure.Process;
using SecAudit.Infrastructure.Registry;
using SecAudit.Infrastructure.Wmi;
using SecAudit.Modules.Hello;
using SecAudit.Plugins.Abstractions;
using SecAudit.Security;
using Serilog;
using Serilog.Events;

namespace SecAudit.App.Bootstrap;

internal static class HostBuilderFactory
{
    public static IHost Build()
    {
        var builder = Host.CreateApplicationBuilder();

        builder.Configuration
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false);

        var logFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAudit", "logs");
        Directory.CreateDirectory(logFolder);
        var logPath = Path.Combine(logFolder, "secaudit-.log");

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .WriteTo.Debug()
            .WriteTo.File(
                logPath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                shared: true)
            .CreateLogger();

        builder.Logging.ClearProviders();
        builder.Logging.AddSerilog(dispose: true);

        // Infrastructure
        builder.Services.AddSingleton<IWmiQuery, WmiQuery>();
        builder.Services.AddSingleton<IRegistryReader, RegistryReader>();
        builder.Services.AddSingleton<IProcessRunner, ProcessRunner>();

        // Security
        builder.Services.AddSingleton<EulaGate>();
        builder.Services.AddSingleton<AuditLog>();

        // Core
        builder.Services.AddSingleton<RiskScoreCalculator>();
        builder.Services.AddTransient<FindingsAggregator>();

        // Modules
        builder.Services.AddSingleton<IAuditModule, HelloModule>();

        // ViewModels
        builder.Services.AddSingleton<ShellViewModel>();
        builder.Services.AddSingleton<DashboardViewModel>();
        builder.Services.AddSingleton<SettingsViewModel>();

        // Views
        builder.Services.AddSingleton<MainWindow>();
        builder.Services.AddTransient<DashboardPage>();
        builder.Services.AddTransient<SettingsPage>();

        return builder.Build();
    }
}
