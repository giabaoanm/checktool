using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecAudit.App.Services;
using SecAudit.App.ViewModels;
using SecAudit.App.Views.Pages;
using SecAudit.App.Views.Shell;
using SecAudit.Core.Services;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Infrastructure.Process;
using SecAudit.Infrastructure.Registry;
using SecAudit.Infrastructure.Wmi;
using SecAudit.Cve.Pipeline;
using SecAudit.Modules.Hardening;
using SecAudit.Modules.Hardening.Checks;
using SecAudit.Modules.Hardening.Remediations;
using SecAudit.Modules.LanScanner;
using SecAudit.Modules.LanScanner.Discovery;
using SecAudit.Modules.LanScanner.Probes;
using SecAudit.Modules.LogForensics;
using SecAudit.Modules.LogForensics.Correlation;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Parsers;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Rules.Sysmon;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Modules.LogForensics.Sources;
using SecAudit.Modules.LogForensics.WebIncident;
using SecAudit.Modules.PatchCve;
using SecAudit.Modules.MalwareInspector;
using SecAudit.Modules.MalwareInspector.Candidates;
using SecAudit.Modules.MalwareInspector.Engine;
using SecAudit.Modules.MalwareInspector.Iocs;
using SecAudit.Modules.MalwareInspector.Rules;
using SecAudit.Modules.RemoteAccess;
using SecAudit.Modules.RemoteAccess.Detectors;
using SecAudit.Modules.DeviceForensics;
using SecAudit.Modules.DeviceForensics.Collectors;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Collectors;
using SecAudit.Reporting;
using SecAudit.Reporting.Writers;
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
        // The WPF shell can audit live OR a mounted offline Windows volume. The user
        // picks at runtime via the Dashboard target picker. We register a
        // MutableOfflineTarget wrapper (default = live); the DashboardViewModel calls
        // .Switch(...) just before each audit run to point modules at the chosen target.
        builder.Services.AddSingleton<MutableOfflineTarget>();
        builder.Services.AddSingleton<IOfflineTarget>(sp => sp.GetRequiredService<MutableOfflineTarget>());
        builder.Services.AddSingleton<IWmiQuery, WmiQuery>();
        builder.Services.AddSingleton<IRegistryReader, RegistryReader>();
        builder.Services.AddSingleton<IRegistryWriter, RegistryWriter>();
        builder.Services.AddSingleton<IProcessRunner, ProcessRunner>();

        // Security
        builder.Services.AddSingleton<EulaGate>();
        builder.Services.AddSingleton<AuditLog>();

        // Core
        builder.Services.AddSingleton<RiskScoreCalculator>();
        builder.Services.AddTransient<FindingsAggregator>();
        builder.Services.AddSingleton<RemediationRegistry>();
        builder.Services.AddSingleton<IncidentResponseActionFactory>();

        // Remediation actions (Module 2 — Hardening)
        builder.Services.AddSingleton<IRemediationAction, AutoRunRemediation>();
        builder.Services.AddSingleton<IRemediationAction, LsaRunAsPplRemediation>();
        builder.Services.AddSingleton<IRemediationAction, PowerShellLoggingRemediation>();
        builder.Services.AddSingleton<IRemediationAction, RdpNlaRemediation>();
        builder.Services.AddSingleton<IRemediationAction, FirewallRemediation>();
        builder.Services.AddSingleton<IRemediationAction, GuestAccountRemediation>();
        builder.Services.AddSingleton<IRemediationAction, SmbV1Remediation>();

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
        builder.Services.AddSingleton<ICheck, FirewallDefaultInboundCheck>();
        builder.Services.AddSingleton<ICheck, FirewallRiskyAllowRulesCheck>();
        builder.Services.AddSingleton<ICheck, FirewallLoggingCheck>();
        builder.Services.AddSingleton<ICheck, ThirdPartyFirewallCheck>();
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

        // Module 5 — Remote Access & Persistence
        builder.Services.AddSingleton<PersistenceDetector>();
        builder.Services.AddSingleton<WmiPersistenceDetector>();
        builder.Services.AddSingleton<ServicesHiveDetector>();
        builder.Services.AddSingleton<ScheduledTasksXmlDetector>();
        builder.Services.AddSingleton<HijackDetector>();
        builder.Services.AddSingleton<IAuditModule, RemoteAccessModule>();

        // Module 8 — Malware Inspector (static analysis + cracker signatures)
        builder.Services.AddSingleton<HashAnalyzer>();
        builder.Services.AddSingleton<AuthenticodeAnalyzer>();
        builder.Services.AddSingleton<PeStructureAnalyzer>();
        builder.Services.AddSingleton<SuspiciousImportAnalyzer>();
        builder.Services.AddSingleton<StringExtractor>();
        builder.Services.AddSingleton<ScriptShortcutAnalyzer>();
        builder.Services.AddSingleton<CrackerSignatureCatalog>();
        builder.Services.AddSingleton<LocalReputationCatalog>();
        builder.Services.AddSingleton<YaraRuleCatalog>();
        builder.Services.AddSingleton<SuspicionScorer>();
        builder.Services.AddSingleton<StaticAnalysisEngine>();
        builder.Services.AddSingleton<CandidateCollector>();
        builder.Services.AddSingleton<IocExporter>();
        builder.Services.AddSingleton<SecAudit.Modules.MalwareInspector.Collectors.AmCacheCollector>();
        builder.Services.AddSingleton<SecAudit.Modules.MalwareInspector.Collectors.SystemPersistenceCollector>();
        builder.Services.AddSingleton<SecAudit.Modules.MalwareInspector.Collectors.PrefetchCollector>();
        builder.Services.AddSingleton<SecAudit.Modules.MalwareInspector.Collectors.LiveProcessCollector>();
        builder.Services.AddSingleton<IAuditModule, MalwareInspectorModule>();

        // Module 6 — Log Forensics / Incident Response
        builder.Services.AddSingleton<ILogParser, WindowsEvtxParser>();
        builder.Services.AddSingleton<ILogParser, WindowsEventXmlParser>();
        builder.Services.AddSingleton<ILogParser, LinuxAuthLogParser>();
        builder.Services.AddSingleton<ILogParser, LinuxSyslogParser>();
        builder.Services.AddSingleton<ILogParser, IisW3cLogParser>();
        builder.Services.AddSingleton<ILogParser, NginxAccessLogParser>();
        builder.Services.AddSingleton<ILogParser, ApacheErrorLogParser>();
        builder.Services.AddSingleton<ILogParser, BashHistoryParser>();
        builder.Services.AddSingleton<IDetectionRule, BruteForceRule>();
        builder.Services.AddSingleton<IDetectionRule, UnknownLogonRule>();
        builder.Services.AddSingleton<IDetectionRule, BackdoorServiceRule>();
        builder.Services.AddSingleton<IDetectionRule, LogClearedRule>();
        builder.Services.AddSingleton<IDetectionRule, VulnScanRule>();
        builder.Services.AddSingleton<IDetectionRule, PrivilegeEscalationRule>();
        builder.Services.AddSingleton<IDetectionRule, KeyloggerRule>();
        builder.Services.AddSingleton<IDetectionRule, RansomwareRule>();
        builder.Services.AddSingleton<IDetectionRule, DataDestructionRule>();
        // Sysmon-centric rules (MITRE ATT&CK ánh xạ) — phủ các kịch bản
        // post-exploitation & persistence mà Security log thông thường không bắt được.
        builder.Services.AddSingleton<IDetectionRule, LsassAccessRule>();
        builder.Services.AddSingleton<IDetectionRule, RemoteThreadInjectionRule>();
        builder.Services.AddSingleton<IDetectionRule, DllSideloadRule>();
        builder.Services.AddSingleton<IDetectionRule, EncodedPowerShellRule>();
        builder.Services.AddSingleton<IDetectionRule, NamedPipeC2Rule>();
        builder.Services.AddSingleton<IDetectionRule, OfficeChildProcessRule>();
        builder.Services.AddSingleton<IDetectionRule, WmiPersistenceRule>();
        builder.Services.AddSingleton<IDetectionRule, SuspiciousScCreateRule>();
        builder.Services.AddSingleton<IDetectionRule, LolBinIngressRule>();
        builder.Services.AddSingleton<IDetectionRule, DefenderTamperingRule>();
        builder.Services.AddSingleton<LocalFolderSource>();
        builder.Services.AddSingleton<WindowsEventLogSource>();
        builder.Services.AddSingleton<SshLogSource>();
        builder.Services.AddSingleton<Func<ForensicsSourceKind, ILogSource>>(sp => kind => kind switch
        {
            ForensicsSourceKind.LocalFolder => sp.GetRequiredService<LocalFolderSource>(),
            ForensicsSourceKind.WindowsEventLog => sp.GetRequiredService<WindowsEventLogSource>(),
            ForensicsSourceKind.SshRemote => sp.GetRequiredService<SshLogSource>(),
            _ => throw new NotSupportedException($"Forensics source {kind} not supported.")
        });
        // Correlation engine — ghép các Finding đã Emit thành kill-chain (MITRE ATT&CK).
        foreach (var chain in PredefinedChains.All())
        {
            builder.Services.AddSingleton<ICorrelationChain>(chain);
        }
        builder.Services.AddSingleton<CorrelationEngine>();
        builder.Services.AddSingleton<LogForensicsEngine>();
        builder.Services.AddSingleton<WebServerEvidenceAnalyzer>();
        builder.Services.AddSingleton<WebIncidentEvidenceCollector>();
        builder.Services.AddSingleton<IAuditModule, LogForensicsModule>();
        builder.Services.AddSingleton<IAuditModule, ServerAttackMonitorModule>();
        builder.Services.AddSingleton<IAuditModule, WebIncidentModule>();

        // Module 9 — Device & Network Forensics
        builder.Services.AddSingleton<DevPropertyReader>();
        builder.Services.AddSingleton<UsbStorageHistoryCollector>();
        builder.Services.AddSingleton<PortableDeviceCollector>();
        builder.Services.AddSingleton<NetworkProfileCollector>();
        builder.Services.AddSingleton<IpConfigCollector>();
        builder.Services.AddSingleton<InternetEgressDetector>();
        builder.Services.AddSingleton<DeviceConnectionEventCollector>();
        builder.Services.AddSingleton<SrumEgressHistoryCollector>();
        builder.Services.AddSingleton<IAuditModule, DeviceForensicsModule>();

        // Reporting
        builder.Services.AddSingleton<IReportWriter, JsonReportWriter>();
        builder.Services.AddSingleton<IReportWriter, HtmlReportWriter>();
        builder.Services.AddSingleton<IReportWriter, PdfReportWriter>();
        builder.Services.AddSingleton<IReportWriter, DocxReportWriter>();
        builder.Services.AddSingleton<ReportService>();
        builder.Services.AddSingleton<ReportSettingsStore>();

        // ViewModels
        builder.Services.AddSingleton<ShellViewModel>();
        builder.Services.AddSingleton<DashboardViewModel>();
        builder.Services.AddSingleton<MalwareTriageViewModel>();
        builder.Services.AddSingleton<SettingsViewModel>();
        builder.Services.AddSingleton<LogForensicsViewModel>();
        builder.Services.AddSingleton<WebIncidentViewModel>();

        // Views
        builder.Services.AddSingleton<MainWindow>();
        builder.Services.AddTransient<DashboardPage>();
        builder.Services.AddTransient<MalwareTriagePage>();
        builder.Services.AddTransient<SettingsPage>();
        builder.Services.AddTransient<LogForensicsPage>();
        builder.Services.AddTransient<WebIncidentPage>();
        builder.Services.AddTransient<HelpPage>();

        return builder.Build();
    }
}
