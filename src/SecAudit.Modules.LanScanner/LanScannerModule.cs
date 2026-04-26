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
        DisplayName: "Kiểm kê mạng LAN",
        Description: "Dò các host đang hoạt động trong subnet nội bộ và phát hiện SMBv1 / RDP-NLA.",
        Category: "Mạng",
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
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang liệt kê subnet nội bộ", 5));
            var subnets = _subnets.Enumerate();
            if (subnets.Count == 0)
            {
                return Done(started, findings, "Không tìm thấy subnet có thể quét");
            }

            // To keep the first pass fast on /24 we only sweep the first subnet. Future
            // work: UI setting to choose subnet / widen scope.
            var subnet = subnets[0];
            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Đang quét {subnet.NetworkAddress}/{subnet.PrefixLength} bằng ARP+ICMP", 15));

            var sweepProgress = new Progress<(int done, int total)>(p =>
            {
                int pct = p.total == 0 ? 30 : 15 + (int)(p.done * 25.0 / p.total);
                progress.Report(new ProgressUpdate(Metadata.Id,
                    $"Quét host {p.done}/{p.total}", Math.Min(40, pct)));
            });
            var alive = await _hosts.SweepAsync(subnet, sweepProgress, cancellationToken).ConfigureAwait(false);

            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Đang quét port trên {alive.Count} host", 45));

            // Buffer per-host port-scan summaries — emitted as ONE consolidated finding
            // after the loop so the report has a single LAN-HOSTS row instead of one per host.
            var hostLines = new List<string>(alive.Count);

            int hostIdx = 0;
            foreach (var host in alive)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hostIdx++;
                int basePct = 45 + (int)(hostIdx * 45.0 / Math.Max(1, alive.Count));
                progress.Report(new ProgressUpdate(Metadata.Id,
                    $"Đang dò {host.Address} ({hostIdx}/{alive.Count})", Math.Min(90, basePct)));

                var open = await _ports.ScanAsync(host.Address, 500, 64, cancellationToken).ConfigureAwait(false);

                if (open.Count > 0)
                {
                    var portList = string.Join(", ", open.Select(p => p.Port));
                    hostLines.Add(
                        $"• {host.Address} — MAC={host.MacAddress ?? "?"}; {open.Count} cổng mở: {portList}");
                }

                if (open.Any(p => p.Port == 445))
                {
                    var smb1Enabled = await _smb1.SupportsSmb1Async(host.Address, 800, cancellationToken).ConfigureAwait(false);
                    if (smb1Enabled == true)
                    {
                        findings.Add(Finding.Create(
                            id: "LAN-SMB1-01",
                            title: $"Host {host.Address} vẫn bật SMBv1",
                            severity: Severity.High,
                            category: "Mạng",
                            asset: host.Address.ToString(),
                            evidence: "Server phản hồi gói SMB1 NT LM 0.12 negotiate bằng trả lời SMB1 — nghĩa là vẫn đang hỗ trợ SMBv1.",
                            remediation: "Tắt SMBv1 (Remove-WindowsFeature FS-SMB1 hoặc Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).",
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
                            title: $"RDP trên {host.Address} không yêu cầu NLA",
                            severity: Severity.High,
                            category: "Mạng",
                            asset: host.Address.ToString(),
                            evidence: "Server cho phép RDP thường (protocol=0x00) trong gói rdpNegRsp — Network Level Authentication đang tắt.",
                            remediation: "Bật NLA: System Properties → Remote → chọn 'Allow connections only from computers running Remote Desktop with NLA'.",
                            references: RefRdpNla));
                    }
                }
            }

            // ONE consolidated row for all hosts with open ports (replaces per-host LAN-HOST-* rows).
            if (hostLines.Count > 0)
            {
                findings.Add(Finding.Create(
                    id: "LAN-HOSTS",
                    title: $"Quét {alive.Count} host đang sống trong subnet — {hostLines.Count} host có cổng TCP mở",
                    severity: Severity.Info,
                    category: "Mạng",
                    asset: $"{subnet.NetworkAddress}/{subnet.PrefixLength}",
                    evidence: string.Join("\n", hostLines),
                    remediation:
                        "Rà soát xem từng dịch vụ có thực sự cần truy cập được từ mạng nội bộ hay không. "
                        + "Với host lạ → đối chiếu MAC với inventory thiết bị; với cổng lạ → 'Test-NetConnection <host> -Port <port>' "
                        + "rồi xác minh nghiệp vụ cần thiết. Cân nhắc segment hoặc firewall chặn ở switch/gateway."));
            }

            progress.Report(new ProgressUpdate(Metadata.Id, "Hoàn tất", 100));
            return Done(started, findings, null);
        }
        catch (OperationCanceledException)
        {
            return Done(started, findings, "Đã bị hủy", succeeded: false);
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
