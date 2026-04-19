using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.LanScanner.Discovery;
using SecAudit.Modules.LanScanner.Models;
using SecAudit.Modules.LanScanner.Probes;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LanScanner;

/// <summary>
/// Iteration 4 module — LAN inventory.
///
/// Scope (SecAudit-Posture): passive discovery only. Enumerate local /24 subnets, sweep
/// alive hosts via ARP+ICMP, TCP-connect a top-ports list, and run two fingerprinting
/// probes (SMBv1 negotiate, RDP NLA). No default-credential probing, no brute force, no
/// vulnerability exploitation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LanScannerModule : IAuditModule
{
    private static readonly string[] RefSmb1 = new[]
    {
        "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
    };
    private static readonly string[] RefRdpNla = new[]
    {
        "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
    };

    private readonly SubnetDiscovery _subnets;
    private readonly HostDiscovery _hosts;
    private readonly PortScanner _ports;
    private readonly SmbV1Probe _smb1;
    private readonly RdpNlaProbe _rdp;
    private readonly ILogger<LanScannerModule> _logger;

    public LanScannerModule(
        SubnetDiscovery subnets,
        HostDiscovery hosts,
        PortScanner ports,
        SmbV1Probe smb1,
        RdpNlaProbe rdp,
        ILogger<LanScannerModule> logger)
    {
        _subnets = subnets;
        _hosts = hosts;
        _ports = ports;
        _smb1 = smb1;
        _rdp = rdp;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "lan-scanner",
        DisplayName: "LAN Inventory",
        Description: "Discover alive hosts on local subnets and fingerprint SMBv1 / RDP-NLA exposure.",
        Category: "Network",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: true,
        DisplayOrder: 40);

    public async Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();

        try
        {
            progress.Report(new ProgressUpdate(Metadata.Id, "Enumerating local subnets", 5));
            var subnets = _subnets.Enumerate();
            if (subnets.Count == 0)
            {
                return Done(started, findings, "No scannable subnet found");
            }

            // To keep the first pass fast on /24 we only sweep the first subnet. Future
            // work: UI setting to choose subnet / widen scope.
            var subnet = subnets[0];
            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Sweeping {subnet.NetworkAddress}/{subnet.PrefixLength} via ARP+ICMP", 15));

            var sweepProgress = new Progress<(int done, int total)>(p =>
            {
                int pct = p.total == 0 ? 30 : 15 + (int)(p.done * 25.0 / p.total);
                progress.Report(new ProgressUpdate(Metadata.Id,
                    $"Host sweep {p.done}/{p.total}", Math.Min(40, pct)));
            });
            var alive = await _hosts.SweepAsync(subnet, sweepProgress, cancellationToken).ConfigureAwait(false);

            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Scanning ports on {alive.Count} host(s)", 45));

            int hostIdx = 0;
            foreach (var host in alive)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hostIdx++;
                int basePct = 45 + (int)(hostIdx * 45.0 / Math.Max(1, alive.Count));
                progress.Report(new ProgressUpdate(Metadata.Id,
                    $"Probing {host.Address} ({hostIdx}/{alive.Count})", Math.Min(90, basePct)));

                var open = await _ports.ScanAsync(host.Address, 500, 64, cancellationToken).ConfigureAwait(false);

                if (open.Count > 0)
                {
                    var portList = string.Join(", ", open.Select(p => p.Port));
                    findings.Add(Finding.Create(
                        id: $"LAN-HOST-{host.Address}",
                        title: $"Host {host.Address} exposes {open.Count} TCP port(s)",
                        severity: Severity.Info,
                        category: "Network",
                        asset: host.Address.ToString(),
                        evidence: $"MAC={host.MacAddress ?? "unknown"}; open ports: {portList}",
                        remediation: "Review whether each service should be reachable on the internal network."));
                }

                if (open.Any(p => p.Port == 445))
                {
                    var smb1Enabled = await _smb1.SupportsSmb1Async(host.Address, 800, cancellationToken).ConfigureAwait(false);
                    if (smb1Enabled == true)
                    {
                        findings.Add(Finding.Create(
                            id: "LAN-SMB1-01",
                            title: $"SMBv1 enabled on {host.Address}",
                            severity: Severity.High,
                            category: "Network",
                            asset: host.Address.ToString(),
                            evidence: "Server responded to SMB1 NT LM 0.12 negotiate with an SMB1 reply.",
                            remediation: "Disable SMBv1 (Remove-WindowsFeature FS-SMB1 or Disable-WindowsOptionalFeature).",
                            references: RefSmb1));
                    }
                }

                if (open.Any(p => p.Port == 3389))
                {
                    var nla = await _rdp.ProbeAsync(host.Address, 800, cancellationToken).ConfigureAwait(false);
                    if (nla == RdpNlaProbe.RdpNlaResult.NlaDisabled)
                    {
                        findings.Add(Finding.Create(
                            id: "LAN-RDP-NLA-01",
                            title: $"RDP on {host.Address} does not require NLA",
                            severity: Severity.High,
                            category: "Network",
                            asset: host.Address.ToString(),
                            evidence: "Server offered plain RDP (protocol=0x00) in rdpNegRsp — Network Level Authentication is off.",
                            remediation: "Enable NLA: System Properties → Remote → 'Allow connections only from computers running Remote Desktop with NLA'.",
                            references: RefRdpNla));
                    }
                }
            }

            progress.Report(new ProgressUpdate(Metadata.Id, "Done", 100));
            return Done(started, findings, null);
        }
        catch (OperationCanceledException)
        {
            return Done(started, findings, "Cancelled", succeeded: false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LanScannerModule failed");
            return Done(started, findings, ex.Message, succeeded: false);
        }
    }

    private ModuleResult Done(DateTimeOffset started, List<object> findings, string? reason, bool succeeded = true)
        => new()
        {
            ModuleId = Metadata.Id,
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            Succeeded = succeeded,
            FailureReason = reason,
            Findings = findings
        };
}
