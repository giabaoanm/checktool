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
using SecAudit.Cve.Pipeline;
using SecAudit.Modules.Hardening;
using SecAudit.Modules.Hardening.Checks;
using SecAudit.Modules.LanScanner;
using SecAudit.Modules.LanScanner.Discovery;
using SecAudit.Modules.LanScanner.Probes;
using SecAudit.Modules.PatchCve;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Collectors;
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

        // Module 1 — System Info & License
        builder.Services.AddSingleton<HardwareInventory>();
        builder.Services.AddSingleton<LicenseChecker>();
        builder.Services.AddSingleton<OfficeKmsPicoDetector>();
        builder.Services.AddSingleton<SoftwareInventory>();
        builder.Services.AddSingleton<IAuditModule, SystemInfoModule>();

        // Module 2 — Hardening (CIS-style)
        builder.Services.AddSingleton<ICheck, UacCheck>();
        builder.Services.AddSingleton<ICheck, SmbV1Check>();
        builder.Services.AddSingleton<ICheck, RdpNlaCheck>();
        builder.Services.AddSingleton<ICheck, FirewallCheck>();
        builder.Services.AddSingleton<ICheck, DefenderCheck>();
        builder.Services.AddSingleton<ICheck, BitLockerCheck>();
        builder.Services.AddSingleton<ICheck, GuestAccountCheck>();
        builder.Services.AddSingleton<ICheck, AutoRunCheck>();
        builder.Services.AddSingleton<ICheck, LsaRunAsPplCheck>();
        builder.Services.AddSingleton<ICheck, PowerShellLoggingCheck>();
        builder.Services.AddSingleton<ICheck, CredentialGuardCheck>();
        builder.Services.AddSingleton<IAuditModule, HardeningModule>();

        // Module 3 — Patch & CVE
        builder.Services.AddSingleton<CveDatabase>();
        builder.Services.AddSingleton<HotfixInventory>();
        builder.Services.AddSingleton<IAuditModule, PatchCveModule>();

        // Module 4 — LAN Inventory
        builder.Services.AddSingleton<SubnetDiscovery>();
        builder.Services.AddSingleton<HostDiscovery>();
        builder.Services.AddSingleton<PortScanner>();
        builder.Services.AddSingleton<SmbV1Probe>();
        builder.Services.AddSingleton<RdpNlaProbe>();
        builder.Services.AddSingleton<IAuditModule, LanScannerModule>();

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
