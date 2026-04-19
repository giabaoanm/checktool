using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging;
using SecAudit.Modules.LanScanner.Models;

namespace SecAudit.Modules.LanScanner.Discovery;

/// <summary>
/// TCP-connect sweep over a curated top-ports list. Uses plain <see cref="TcpClient"/>
/// connects (the same thing nmap falls back to in "-sT" mode) so no raw-socket / Npcap
/// dependency — keeps the tool portable.
/// </summary>
public sealed class PortScanner
{
    private const string PortsResource = "SecAudit.Modules.LanScanner.Resources.top-ports.txt";
    private readonly ILogger<PortScanner> _logger;
    private readonly int[] _ports;

    public PortScanner(ILogger<PortScanner> logger)
    {
        _logger = logger;
        _ports = LoadPorts();
    }

    public IReadOnlyList<int> Ports => _ports;

    public async Task<IReadOnlyList<OpenPort>> ScanAsync(
        IPAddress host,
        int timeoutMs,
        int maxParallel,
        CancellationToken ct)
    {
        var sem = new SemaphoreSlim(maxParallel);
        var open = new ConcurrentBag<OpenPort>();
        var tasks = _ports.Select(async port =>
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (await IsOpenAsync(host, port, timeoutMs, ct).ConfigureAwait(false))
                {
                    open.Add(new OpenPort(host, port, null));
                }
            }
            finally
            {
                sem.Release();
            }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        return open.OrderBy(p => p.Port).ToArray();
    }

    private static async Task<bool> IsOpenAsync(IPAddress host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static int[] LoadPorts()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(PortsResource)
            ?? throw new InvalidOperationException("Missing embedded resource: " + PortsResource);
        using var reader = new StreamReader(stream);
        var list = new List<int>();
        while (reader.ReadLine() is { } line)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }
            if (int.TryParse(trimmed, out var p) && p is > 0 and < 65536)
            {
                list.Add(p);
            }
        }
        return list.Distinct().OrderBy(p => p).ToArray();
    }
}
