using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Cve.Pipeline;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Infrastructure.Process;
using SecAudit.Infrastructure.Registry;
using SecAudit.Infrastructure.Wmi;
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
using SecAudit.Modules.PatchCve;
using SecAudit.Modules.MalwareInspector;
using SecAudit.Modules.MalwareInspector.Candidates;
using SecAudit.Modules.MalwareInspector.Engine;
using SecAudit.Modules.MalwareInspector.Iocs;
using SecAudit.Modules.MalwareInspector.Models;
using SecAudit.Modules.MalwareInspector.Rules;
using SecAudit.Modules.RemoteAccess;
using SecAudit.Modules.RemoteAccess.Detectors;
using SecAudit.Modules.DeviceForensics;
using SecAudit.Modules.DeviceForensics.Collectors;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Collectors;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;
using SecAudit.Reporting;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;
using SecAudit.Reporting.Writers;
using SecAudit.Security;
using Serilog;
using Serilog.Events;

namespace SecAudit.Cli;

internal static class Program
{
    private const string Help = """
        SecAudit.Cli — headless audit runner.

        Usage:
          SecAudit.Cli [options]

        Options:
          --offline <drive>  Audit a Windows volume mounted offline (WinPE scenario).
                             Example: --offline D:\
                             Only PatchCve, RemoteAccess, LogForensics run meaningfully in
                             offline mode — other modules are skipped with an info finding.
          --output <dir>     Folder to write reports into (default: current directory)
          --asset <name>     Override asset/machine name in reports (default: %COMPUTERNAME%
                             live, or <drive>-OFFLINE in offline mode)
          --formats <list>   Comma-separated subset of: html,pdf,json,docx (default: all)
          --quiet            Suppress per-module progress lines (errors still printed)
          -h, --help         Show this help

        Exit codes:
          0  audit completed and reports written
          2  one or more modules failed
          3  unhandled exception
          64 invalid command line
        """;

    public static async Task<int> Main(string[] args)
    {
        try
        {
            var opts = ParseArgs(args);
            if (opts is null)
            {
                return 64;
            }
            if (opts.ShowHelp)
            {
                Console.WriteLine(Help);
                return 0;
            }

            // When the caller forgot --offline but we're on a WinPE boot image, nudge them:
            // otherwise the live-mode audit will try to probe WinPE's own (tiny) volume and
            // produce nonsense findings. We only print a hint — we don't block the run.
            if (opts.OfflineVolume is null && WinPeEnvironment.IsRunningInWinPe())
            {
                Console.Error.WriteLine(
                    "[hint] Running inside WinPE but --offline was not supplied. The audit will " +
                    "target the live WinPE environment, which is rarely what you want. Re-run with " +
                    "--offline <drive-letter> to audit a mounted Windows volume.");
            }

            using var host = BuildHost(opts);
            return await RunAsync(host, opts).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FATAL: " + ex);
            return 3;
        }
    }

    // Module IDs that are meaningful when auditing a mounted volume (everything else
    // depends on live WMI / runtime state and would produce garbage offline).
    private static readonly HashSet<string> OfflineCapableModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "patch-cve",
        "remote-access",
        "log-forensics"
    };

    private static async Task<int> RunAsync(IHost host, CliOptions opts)
    {
        var sp = host.Services;
        var modules = sp.GetServices<IAuditModule>().OrderBy(m => m.Metadata.DisplayOrder).ToList();
        if (opts.IsOffline)
        {
            var skipped = modules.Where(m => !OfflineCapableModules.Contains(m.Metadata.Id)).ToList();
            modules = modules.Where(m => OfflineCapableModules.Contains(m.Metadata.Id)).ToList();
            foreach (var m in skipped)
            {
                Console.WriteLine($"-- skipping {m.Metadata.Id} (not supported in --offline mode)");
            }
        }
        var scorer = sp.GetRequiredService<RiskScoreCalculator>();
        var reports = sp.GetRequiredService<ReportService>();
        var settingsStore = sp.GetRequiredService<ReportSettingsStore>();
        var log = sp.GetRequiredService<ILogger<CliOptions>>();

        var options = new Dictionary<string, string>(StringComparer.Ordinal);

        // When running --offline, auto-configure LogForensics to snapshot the target volume's
        // event-log folder. The module is normally interactive (skipped when no settings are
        // present); offline mode is the one place where an auto-run makes sense — we already
        // have the volume root and there's no operator in the loop.
        if (opts.IsOffline)
        {
            var offlineTarget = sp.GetRequiredService<SecAudit.Infrastructure.OfflineTarget.IOfflineTarget>();
            var eventLogDir = Path.Combine(offlineTarget.WindowsDirectory, "System32", "winevt", "Logs");
            if (Directory.Exists(eventLogDir))
            {
                var forensicsSettings = new SecAudit.Modules.LogForensics.Models.ForensicsSettings
                {
                    SourceKind = SecAudit.Modules.LogForensics.Models.ForensicsSourceKind.LocalFolder,
                    LocalPath = eventLogDir,
                    LocalRecursive = false
                };
                options[SecAudit.Modules.LogForensics.LogForensicsModule.OptionKey] =
                    System.Text.Json.JsonSerializer.Serialize(forensicsSettings);
                Console.WriteLine($"[offline] LogForensics will scan: {eventLogDir}");
            }
            else
            {
                Console.Error.WriteLine($"[offline] Event log folder not found at {eventLogDir} — LogForensics will no-op.");
            }
        }

        var context = new ScanContext
        {
            MachineName = opts.AssetName,
            CurrentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown",
            StartedAt = DateTimeOffset.UtcNow,
            Options = options
        };

        var aggregator = new FindingsAggregator();
        var allFindings = new List<Finding>();
        bool anyModuleFailed = false;

        IProgress<ProgressUpdate> progress = opts.Quiet
            ? new Progress<ProgressUpdate>(_ => { })
            : new Progress<ProgressUpdate>(u => Console.WriteLine(
                $"[{u.PercentComplete,3}%] [{u.ModuleId}] {u.Message}"));

        foreach (var module in modules)
        {
            Console.WriteLine($"==> {module.Metadata.Id} ({module.Metadata.DisplayName})");
            try
            {
                var result = await module.RunAsync(context, progress, CancellationToken.None).ConfigureAwait(false);
                aggregator.Add(result);
                foreach (var raw in result.Findings)
                {
                    if (raw is Finding f)
                    {
                        allFindings.Add(f);
                    }
                }
                if (!result.Succeeded)
                {
                    anyModuleFailed = true;
                    Console.Error.WriteLine($"    module failed: {result.FailureReason}");
                }
                else
                {
                    var newCount = result.Findings.OfType<Finding>().Count();
                    Console.WriteLine($"    {newCount} finding(s)");
                }
            }
            catch (Exception ex)
            {
                anyModuleFailed = true;
                log.LogError(ex, "Module {Module} threw", module.Metadata.Id);
                Console.Error.WriteLine($"    EXCEPTION: {ex.Message}");
            }
        }

        var score = scorer.Score(allFindings);
        Console.WriteLine();
        Console.WriteLine($"Score: {score.Value} ({score.Band})    Findings: {allFindings.Count}");

        // Build device profile + new baseline sections (License / Patch / Scope) for
        // Section II. Pulling each shared snapshot from the ScanContext keeps modules
        // de-coupled from the reporting layer.
        var inv = context.GetShared<SystemInventory>(SystemInfoModule.SharedInventoryKey);
        var patchSnap = context.GetShared<PatchSnapshot>(PatchCveModule.SharedSnapshotKey);
        var raSnap = context.GetShared<RemoteAccessSnapshot>(RemoteAccessModule.SharedSnapshotKey);
        var forensicsResult = context.GetShared<ForensicsResult>("log-forensics.result");

        var device = BuildDeviceProfile(inv);
        var license = BuildLicenseSummary(inv);
        var patch = BuildPatchSummary(patchSnap);
        var scope = BuildScanScope(raSnap, forensicsResult);

        // Filter writers per --formats option. CLI loads metadata silently from disk —
        // the interactive dialog only runs in the WPF shell. If the file is missing we
        // fall back to an all-blank ReportSettings so the form prints with hand-fill dots.
        var metadata = settingsStore.Load();
        var data = reports.BuildData(
            aggregator, score, opts.AssetName, device,
            appliedActions: Array.Empty<AppliedAction>(),
            metadata: metadata,
            license: license,
            patch: patch,
            scope: scope);
        var written = await reports.WriteAllAsync(data, opts.OutputDir, CancellationToken.None).ConfigureAwait(false);
        // If user asked for a subset, delete others. Cheap for 3 files; keeps the writer
        // pipeline simple and avoids exposing format selection through ReportService.
        if (opts.Formats is not null)
        {
            foreach (var path in written)
            {
                var ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
                if (!opts.Formats.Contains(ext))
                {
                    try { File.Delete(path); } catch { /* best-effort */ }
                }
            }
            written = written.Where(p =>
                opts.Formats.Contains(Path.GetExtension(p).TrimStart('.').ToLowerInvariant())).ToList();
        }

        Console.WriteLine();
        Console.WriteLine($"Reports written to: {Path.GetFullPath(opts.OutputDir)}");
        foreach (var p in written)
        {
            Console.WriteLine("  " + Path.GetFileName(p));
        }

        // IOC hand-off bundle (txt/csv/regkeys) for Kaspersky / regedit triage. Uses the
        // same prefix as the regular reports so all artifacts collate together.
        var malSnap = context.GetShared<MalwareInspectorSnapshot>(MalwareInspectorModule.SharedSnapshotKey);
        if (malSnap is not null && malSnap.IocEntries.Count > 0)
        {
            var exporter = sp.GetRequiredService<IocExporter>();
            var stamp = data.GeneratedAt.ToString("yyyyMMdd-HHmmss");
            var prefix = $"secaudit-{opts.AssetName}-{stamp}";
            var iocResult = exporter.Export(malSnap.IocEntries, opts.OutputDir, prefix);
            if (iocResult.WrittenPaths.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine("IOC list xuất ra (paste vào Kaspersky → Custom Scan → Add objects):");
                foreach (var p in iocResult.WrittenPaths)
                {
                    Console.WriteLine("  " + Path.GetFileName(p));
                }
            }
            foreach (var err in iocResult.Errors)
            {
                Console.Error.WriteLine("[ioc-export] " + err);
            }
        }

        return anyModuleFailed ? 2 : 0;
    }

    private static IHost BuildHost(CliOptions opts)
    {
        var builder = Host.CreateApplicationBuilder();

        var logFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAudit", "logs");
        Directory.CreateDirectory(logFolder);
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .WriteTo.File(Path.Combine(logFolder, "secaudit-cli-.log"),
                rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14, shared: true)
            .CreateLogger();
        builder.Logging.ClearProviders();
        builder.Logging.AddSerilog(dispose: true);

        var s = builder.Services;
        // Infrastructure — swap the offline target based on --offline.
        // MountedVolumeOfflineTarget performs RegLoadKey in its constructor, so we resolve
        // the factory lazily (so CLI --help doesn't fail) and let DI own the lifetime —
        // disposal happens via Host.Dispose → IDisposable chain.
        if (opts.OfflineVolume is { } offlineRoot)
        {
            s.AddSingleton<IOfflineTarget>(_ => new MountedVolumeOfflineTarget(offlineRoot));
        }
        else
        {
            s.AddSingleton<IOfflineTarget, LiveOfflineTarget>();
        }
        s.AddSingleton<IWmiQuery, WmiQuery>();
        s.AddSingleton<IRegistryReader, RegistryReader>();
        s.AddSingleton<IRegistryWriter, RegistryWriter>();
        s.AddSingleton<IProcessRunner, ProcessRunner>();
        // Security / Core
        s.AddSingleton<EulaGate>();
        s.AddSingleton<AuditLog>();
        s.AddSingleton<RiskScoreCalculator>();
        s.AddTransient<FindingsAggregator>();
        s.AddSingleton<RemediationRegistry>();
        // Remediation actions
        s.AddSingleton<IRemediationAction, AutoRunRemediation>();
        s.AddSingleton<IRemediationAction, LsaRunAsPplRemediation>();
        s.AddSingleton<IRemediationAction, PowerShellLoggingRemediation>();
        s.AddSingleton<IRemediationAction, RdpNlaRemediation>();
        s.AddSingleton<IRemediationAction, FirewallRemediation>();
        s.AddSingleton<IRemediationAction, GuestAccountRemediation>();
        s.AddSingleton<IRemediationAction, SmbV1Remediation>();
        // Module 1 — System Info
        s.AddSingleton<HardwareInventory>();
        s.AddSingleton<LicenseChecker>();
        s.AddSingleton<OfficeKmsPicoDetector>();
        s.AddSingleton<SoftwareInventory>();
        s.AddSingleton<IAuditModule, SystemInfoModule>();
        // Module 2 — Hardening
        s.AddSingleton<ICheck, UacCheck>();
        s.AddSingleton<ICheck, SmbV1Check>();
        s.AddSingleton<ICheck, RdpNlaCheck>();
        s.AddSingleton<ICheck, FirewallCheck>();
        s.AddSingleton<ICheck, FirewallDefaultInboundCheck>();
        s.AddSingleton<ICheck, FirewallRiskyAllowRulesCheck>();
        s.AddSingleton<ICheck, FirewallLoggingCheck>();
        s.AddSingleton<ICheck, ThirdPartyFirewallCheck>();
        s.AddSingleton<ICheck, DefenderCheck>();
        s.AddSingleton<ICheck, BitLockerCheck>();
        s.AddSingleton<ICheck, GuestAccountCheck>();
        s.AddSingleton<ICheck, AutoRunCheck>();
        s.AddSingleton<ICheck, LsaRunAsPplCheck>();
        s.AddSingleton<ICheck, PowerShellLoggingCheck>();
        s.AddSingleton<ICheck, CredentialGuardCheck>();
        s.AddSingleton<IAuditModule, HardeningModule>();
        // Module 3 — Patch & CVE
        s.AddSingleton<CveDatabase>();
        s.AddSingleton<HotfixInventory>();
        s.AddSingleton<IAuditModule, PatchCveModule>();
        // Module 4 — LAN
        s.AddSingleton<SubnetDiscovery>();
        s.AddSingleton<HostDiscovery>();
        s.AddSingleton<PortScanner>();
        s.AddSingleton<SmbV1Probe>();
        s.AddSingleton<RdpNlaProbe>();
        s.AddSingleton<IAuditModule, LanScannerModule>();
        // Module 5 — Remote Access
        s.AddSingleton<PersistenceDetector>();
        s.AddSingleton<WmiPersistenceDetector>();
        s.AddSingleton<ServicesHiveDetector>();
        s.AddSingleton<ScheduledTasksXmlDetector>();
        s.AddSingleton<IAuditModule, RemoteAccessModule>();
        // Module 8 — Malware Inspector (static analysis + cracker signatures)
        s.AddSingleton<HashAnalyzer>();
        s.AddSingleton<AuthenticodeAnalyzer>();
        s.AddSingleton<PeStructureAnalyzer>();
        s.AddSingleton<SuspiciousImportAnalyzer>();
        s.AddSingleton<StringExtractor>();
        s.AddSingleton<CrackerSignatureCatalog>();
        s.AddSingleton<SuspicionScorer>();
        s.AddSingleton<StaticAnalysisEngine>();
        s.AddSingleton<CandidateCollector>();
        s.AddSingleton<IocExporter>();
        s.AddSingleton<IAuditModule, MalwareInspectorModule>();
        // Module 6 — Log Forensics
        s.AddSingleton<ILogParser, WindowsEvtxParser>();
        s.AddSingleton<ILogParser, WindowsEventXmlParser>();
        s.AddSingleton<ILogParser, LinuxAuthLogParser>();
        s.AddSingleton<ILogParser, LinuxSyslogParser>();
        s.AddSingleton<ILogParser, IisW3cLogParser>();
        s.AddSingleton<ILogParser, NginxAccessLogParser>();
        s.AddSingleton<ILogParser, ApacheErrorLogParser>();
        s.AddSingleton<ILogParser, BashHistoryParser>();
        s.AddSingleton<IDetectionRule, BruteForceRule>();
        s.AddSingleton<IDetectionRule, UnknownLogonRule>();
        s.AddSingleton<IDetectionRule, BackdoorServiceRule>();
        s.AddSingleton<IDetectionRule, LogClearedRule>();
        s.AddSingleton<IDetectionRule, VulnScanRule>();
        s.AddSingleton<IDetectionRule, PrivilegeEscalationRule>();
        s.AddSingleton<IDetectionRule, KeyloggerRule>();
        s.AddSingleton<IDetectionRule, RansomwareRule>();
        s.AddSingleton<IDetectionRule, DataDestructionRule>();
        // Sysmon-centric rules (mirror with App host)
        s.AddSingleton<IDetectionRule, LsassAccessRule>();
        s.AddSingleton<IDetectionRule, RemoteThreadInjectionRule>();
        s.AddSingleton<IDetectionRule, DllSideloadRule>();
        s.AddSingleton<IDetectionRule, EncodedPowerShellRule>();
        s.AddSingleton<IDetectionRule, NamedPipeC2Rule>();
        s.AddSingleton<IDetectionRule, OfficeChildProcessRule>();
        s.AddSingleton<IDetectionRule, WmiPersistenceRule>();
        s.AddSingleton<IDetectionRule, SuspiciousScCreateRule>();
        s.AddSingleton<IDetectionRule, LolBinIngressRule>();
        s.AddSingleton<IDetectionRule, DefenderTamperingRule>();
        s.AddSingleton<LocalFolderSource>();
        s.AddSingleton<WindowsEventLogSource>();
        s.AddSingleton<SshLogSource>();
        s.AddSingleton<Func<ForensicsSourceKind, ILogSource>>(sp => kind => kind switch
        {
            ForensicsSourceKind.LocalFolder => sp.GetRequiredService<LocalFolderSource>(),
            ForensicsSourceKind.WindowsEventLog => sp.GetRequiredService<WindowsEventLogSource>(),
            ForensicsSourceKind.SshRemote => sp.GetRequiredService<SshLogSource>(),
            _ => throw new NotSupportedException($"Forensics source {kind} not supported.")
        });
        foreach (var chain in PredefinedChains.All())
        {
            s.AddSingleton<ICorrelationChain>(chain);
        }
        s.AddSingleton<CorrelationEngine>();
        s.AddSingleton<LogForensicsEngine>();
        s.AddSingleton<IAuditModule, LogForensicsModule>();
        // Module 9 — Device & Network Forensics (USB/phone history, network profiles, IP plan)
        s.AddSingleton<DevPropertyReader>();
        s.AddSingleton<UsbStorageHistoryCollector>();
        s.AddSingleton<PortableDeviceCollector>();
        s.AddSingleton<NetworkProfileCollector>();
        s.AddSingleton<IpConfigCollector>();
        s.AddSingleton<InternetEgressDetector>();
        s.AddSingleton<DeviceConnectionEventCollector>();
        s.AddSingleton<SrumEgressHistoryCollector>();
        s.AddSingleton<IAuditModule, DeviceForensicsModule>();
        // Reporting
        s.AddSingleton<IReportWriter, JsonReportWriter>();
        s.AddSingleton<IReportWriter, HtmlReportWriter>();
        s.AddSingleton<IReportWriter, PdfReportWriter>();
        s.AddSingleton<IReportWriter, DocxReportWriter>();
        s.AddSingleton<ReportService>();
        s.AddSingleton<ReportSettingsStore>();

        return builder.Build();
    }

    /// <summary>
    /// Translate the collected <see cref="SystemInventory"/> plus a fresh NIC scan into
    /// the <see cref="DeviceProfile"/> used by the formal report header. Mirror of the
    /// equivalent method in <c>SecAudit.App.ViewModels.ReportSectionBuilder</c>;
    /// duplicated to keep the dependency graph one-way (App and CLI both depend on
    /// Modules + Reporting; Reporting must not depend on Modules).
    /// </summary>
    private static DeviceProfile BuildDeviceProfile(SystemInventory? inv)
    {
        var nics = NetworkAddressCollector.Collect();
        if (inv is null)
        {
            return new DeviceProfile(
                ComputerName: Environment.MachineName,
                Cpu: "(unknown)",
                CpuCores: 0,
                CpuLogicalProcessors: 0,
                BiosSerial: "(unknown)",
                BiosVendor: "(unknown)",
                BiosVersion: null,
                BiosReleaseDate: null,
                TotalRam: "(unknown)",
                OperatingSystem: Environment.OSVersion.VersionString,
                Disks: Array.Empty<DiskSummary>(),
                NetworkAddresses: nics,
                TpmPresent: false,
                TpmSpecVersion: null,
                SecureBootEnabled: false);
        }
        var ramGb = inv.Hardware.TotalPhysicalMemoryBytes / (1024.0 * 1024 * 1024);
        var disks = inv.Hardware.Disks
            .Select(d => new DiskSummary(
                Model: d.Model,
                InterfaceType: d.InterfaceType,
                Size: FormatGb(d.SizeBytes),
                SerialNumber: d.SerialNumber))
            .ToArray();
        return new DeviceProfile(
            ComputerName: Environment.MachineName,
            Cpu: $"{inv.Hardware.CpuName} ({inv.Hardware.CpuCores}C/{inv.Hardware.CpuLogicalProcessors}T)",
            CpuCores: inv.Hardware.CpuCores,
            CpuLogicalProcessors: inv.Hardware.CpuLogicalProcessors,
            BiosSerial: string.IsNullOrWhiteSpace(inv.Hardware.SerialNumber) ? "(không có)" : inv.Hardware.SerialNumber,
            BiosVendor: string.IsNullOrWhiteSpace(inv.Hardware.BiosVendor) ? "(không xác định)" : inv.Hardware.BiosVendor,
            BiosVersion: string.IsNullOrWhiteSpace(inv.Hardware.BiosVersion) ? null : inv.Hardware.BiosVersion,
            BiosReleaseDate: inv.Hardware.BiosReleaseDate,
            TotalRam: ramGb >= 0.5 ? $"{ramGb:0.0} GB" : "(unknown)",
            OperatingSystem: $"{inv.OperatingSystem.Caption} build {inv.OperatingSystem.BuildNumber} ({inv.OperatingSystem.DisplayVersion})",
            Disks: disks,
            NetworkAddresses: nics,
            TpmPresent: inv.Hardware.TpmPresent,
            TpmSpecVersion: inv.Hardware.TpmSpecVersion,
            SecureBootEnabled: inv.Hardware.SecureBootEnabled);
    }

    private static LicenseSummary? BuildLicenseSummary(SystemInventory? inv)
    {
        if (inv is null) { return null; }
        return new LicenseSummary(
            Windows: ToLicenseEntry(inv.WindowsLicense),
            Office: inv.OfficeLicenses.Select(ToLicenseEntry).ToArray(),
            OfficeKmsPicoSuspected: inv.OfficeKmsPicoSuspected,
            OfficeKmsPicoEvidence: inv.OfficeKmsPicoEvidence);
    }

    private static PatchSummary? BuildPatchSummary(PatchSnapshot? snap)
    {
        if (snap is null) { return null; }
        return new PatchSummary(
            InstalledKbCount: snap.InstalledKbCount,
            MissingCriticalRuleCount: snap.MissingCriticalRuleCount,
            CveDbLastSync: snap.CveDbLastSync,
            CveDbStale: snap.CveDbStale);
    }

    private static ScanScope? BuildScanScope(RemoteAccessSnapshot? ra, ForensicsResult? forensics)
    {
        if (ra is null && forensics is null) { return null; }
        return new ScanScope(
            AutorunTotal: ra?.AutorunTotal,
            AutorunSuspicious: ra?.AutorunSuspicious,
            ServiceSuspicious: ra?.ServiceSuspicious,
            ScheduledTaskSuspicious: ra?.ScheduledTaskSuspicious,
            WmiPersistenceCount: ra?.WmiPersistenceCount,
            ForensicsRun: forensics is not null,
            ForensicsSessionId: forensics?.SessionId,
            ForensicsTotalFiles: forensics?.TotalFiles,
            ForensicsTotalRecords: forensics?.TotalRecords,
            ForensicsManifestCount: forensics?.Manifest.Count,
            ForensicsEvidenceRoot: forensics?.EvidenceRoot);
    }

    private static LicenseEntry ToLicenseEntry(LicenseInfo li) => new(
        Product: li.Product,
        StatusCode: li.LicenseStatus,
        StatusText: li.LicenseStatusText,
        Description: li.Description,
        PartialProductKey: li.PartialProductKey,
        KmsServer: li.KmsServer,
        IsGenuine: li.IsGenuine);

    private static string FormatGb(long bytes)
    {
        var gb = bytes / (1024.0 * 1024 * 1024);
        return gb >= 1
            ? gb.ToString("0.0", CultureInfo.InvariantCulture) + " GB"
            : (bytes / (1024.0 * 1024)).ToString("0", CultureInfo.InvariantCulture) + " MB";
    }

    private sealed class CliOptions
    {
        public string OutputDir { get; init; } = Environment.CurrentDirectory;
        public string AssetName { get; init; } = Environment.MachineName;
        public HashSet<string>? Formats { get; init; }
        public bool Quiet { get; init; }
        public bool ShowHelp { get; init; }

        /// <summary>
        /// Absolute path to the root of a mounted Windows volume when --offline was passed
        /// (e.g. "D:\"). Null for live-OS mode.
        /// </summary>
        public string? OfflineVolume { get; init; }

        /// <summary>True when running in offline (mounted volume) mode.</summary>
        public bool IsOffline => OfflineVolume is not null;
    }

    private static CliOptions? ParseArgs(string[] args)
    {
        string outputDir = Environment.CurrentDirectory;
        string asset = Environment.MachineName;
        HashSet<string>? formats = null;
        bool quiet = false;
        bool help = false;
        string? offlineVolume = null;
        bool assetExplicit = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-h":
                case "--help":
                    help = true;
                    break;
                case "--quiet":
                    quiet = true;
                    break;
                case "--offline":
                    if (++i >= args.Length) { Console.Error.WriteLine("--offline requires a drive letter or path (e.g. D:\\)"); return null; }
                    offlineVolume = args[i];
                    break;
                case "--output":
                    if (++i >= args.Length) { Console.Error.WriteLine("--output requires a value"); return null; }
                    outputDir = args[i];
                    break;
                case "--asset":
                    if (++i >= args.Length) { Console.Error.WriteLine("--asset requires a value"); return null; }
                    asset = args[i];
                    assetExplicit = true;
                    break;
                case "--formats":
                    if (++i >= args.Length) { Console.Error.WriteLine("--formats requires a value"); return null; }
                    formats = args[i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                     .Select(f => f.ToLower(CultureInfo.InvariantCulture))
                                     .ToHashSet();
                    var valid = new HashSet<string> { "html", "pdf", "json", "docx" };
                    if (!formats.IsSubsetOf(valid))
                    {
                        Console.Error.WriteLine("--formats accepts only: html, pdf, json, docx");
                        return null;
                    }
                    break;
                default:
                    Console.Error.WriteLine($"Unknown argument: {a}");
                    return null;
            }
        }

        // Default asset name in offline mode is "<drive>-OFFLINE" because %COMPUTERNAME% refers
        // to the WinPE environment, not the volume being audited.
        if (offlineVolume is not null && !assetExplicit)
        {
            var letter = offlineVolume.Trim().TrimEnd('\\', '/');
            asset = (letter.Length > 0 ? letter : "VOLUME") + "-OFFLINE";
        }

        return new CliOptions
        {
            OutputDir = outputDir,
            AssetName = asset,
            Formats = formats,
            Quiet = quiet,
            ShowHelp = help,
            OfflineVolume = offlineVolume
        };
    }
}
