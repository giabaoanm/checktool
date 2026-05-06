using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Process;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.App.Services;

/// <summary>
/// Creates per-finding response actions for live incident findings.
/// Fixed hardening remediations still come from RemediationRegistry.
/// </summary>
public sealed class IncidentResponseActionFactory
{
    private static readonly Regex Ipv4Regex = new(
        @"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly HashSet<string> BlockableCategories = new(StringComparer.OrdinalIgnoreCase)
    {
        "server-attack.brute-force",
        "server-attack.web-scan",
        "server-attack.compromise-suspected"
    };

    private readonly IProcessRunner _runner;

    public IncidentResponseActionFactory(IProcessRunner runner) => _runner = runner;

    public IRemediationAction? TryCreate(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (!BlockableCategories.Contains(finding.Category)
            || finding.Severity < Severity.High)
        {
            return null;
        }

        var ip = TryExtractRemoteIp(finding);
        return ip is null
            ? null
            : new BlockRemoteIpAction(finding.Id, ip, _runner);
    }

    private static IPAddress? TryExtractRemoteIp(Finding finding)
    {
        if (finding.Asset.StartsWith("ip:", StringComparison.OrdinalIgnoreCase)
            && TryParseUsableIpv4(finding.Asset[3..], out var assetIp))
        {
            return assetIp;
        }

        foreach (Match match in Ipv4Regex.Matches(finding.Evidence))
        {
            if (TryParseUsableIpv4(match.Value, out var evidenceIp))
            {
                return evidenceIp;
            }
        }

        return null;
    }

    private static bool TryParseUsableIpv4(string value, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (!IPAddress.TryParse(value.Trim(), out var parsed)
            || parsed.AddressFamily != AddressFamily.InterNetwork
            || IPAddress.IsLoopback(parsed)
            || parsed.Equals(IPAddress.Any)
            || parsed.Equals(IPAddress.Broadcast))
        {
            return false;
        }

        ip = parsed;
        return true;
    }

    private sealed class BlockRemoteIpAction : IRemediationAction
    {
        private readonly IPAddress _ip;
        private readonly IProcessRunner _runner;

        public BlockRemoteIpAction(string findingId, IPAddress ip, IProcessRunner runner)
        {
            FindingId = findingId;
            _ip = ip;
            _runner = runner;
        }

        public string FindingId { get; }
        public string Title => "Chan IP nguon";
        public string Description =>
            $"Them rule Windows Firewall chan inbound tu IP {_ip}. "
            + "Hanh dong nay chi nen ap dung khi IP nguon khong phai dia chi quan tri/hop le cua don vi.";
        public bool RequiresReboot => false;
        public bool RequiresAdmin => true;

        public async Task<RemediationResult> ApplyAsync(CancellationToken cancellationToken)
        {
            var ruleName = BuildRuleName(FindingId, _ip);

            try
            {
                var show = await _runner.RunAsync(
                    "netsh.exe",
                    $"advfirewall firewall show rule name=\"{ruleName}\"",
                    TimeSpan.FromSeconds(10),
                    cancellationToken).ConfigureAwait(false);
                if (show.ExitCode == 0
                    && show.StandardOutput.Contains(ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    return new RemediationResult(
                        Succeeded: true,
                        Message: $"Da co rule chan IP {_ip}.",
                        RebootRequired: false);
                }

                var add = await _runner.RunAsync(
                    "netsh.exe",
                    "advfirewall firewall add rule "
                    + $"name=\"{ruleName}\" "
                    + "dir=in action=block "
                    + $"remoteip={_ip} "
                    + "enable=yes profile=any",
                    TimeSpan.FromSeconds(10),
                    cancellationToken).ConfigureAwait(false);

                if (add.ExitCode == 0)
                {
                    return new RemediationResult(
                        Succeeded: true,
                        Message: $"Da chan inbound tu IP {_ip} bang Windows Firewall.",
                        RebootRequired: false);
                }

                var detail = string.IsNullOrWhiteSpace(add.StandardError)
                    ? add.StandardOutput.Trim()
                    : add.StandardError.Trim();
                return new RemediationResult(
                    Succeeded: false,
                    Message: $"netsh tra ve ma {add.ExitCode}. {detail}",
                    RebootRequired: false);
            }
            catch (Exception ex)
            {
                return new RemediationResult(
                    Succeeded: false,
                    Message: $"Loi khi them firewall rule: {ex.Message}",
                    RebootRequired: false);
            }
        }

        private static string BuildRuleName(string findingId, IPAddress ip)
        {
            var shortId = findingId.Length <= 28 ? findingId : findingId[..28];
            return $"SecAudit Block {ip} {shortId}";
        }
    }
}
