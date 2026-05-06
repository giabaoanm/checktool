using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Parsers;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Sources;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics;

/// <summary>
/// Fast live triage for Windows servers. It inspects recent Security/System/Sysmon
/// events, IIS W3C logs, and the current TCP table to surface online attack patterns.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServerAttackMonitorModule : IAuditModule
{
    public const string OptionLookbackMinutesKey = "server-attack-monitor.lookback-minutes";
    public const string SharedSnapshotKey = "server-attack-monitor.snapshot";

    private const int DefaultLookbackMinutes = 1440;
    private const int MaxEventRecordsPerChannel = 50000;

    private readonly IEnumerable<ILogParser> _parsers;
    private readonly ILogger<ServerAttackMonitorModule> _logger;

    public ServerAttackMonitorModule(
        IEnumerable<ILogParser> parsers,
        ILogger<ServerAttackMonitorModule> logger)
    {
        _parsers = parsers;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "server-attack-monitor",
        DisplayName: "Phat hien tan cong truc tuyen may chu",
        Description: "Quet nhanh Security/Sysmon/IIS va ket noi TCP hien tai de phat hien brute-force, web scan, RCE/webshell, credential dump va truy cap cong quan tri.",
        Category: "Ung cuu su co",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: true,
        DisplayOrder: 75);

    public async Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();

        var lookbackMinutes = ResolveLookbackMinutes(context);
        var fromUtc = DateTimeOffset.UtcNow.AddMinutes(-lookbackMinutes);
        var analyzer = new ServerAttackAnalyzer();
        int records = 0;
        int sourceCount = 0;

        try
        {
            progress.Report(new ProgressUpdate(Metadata.Id, "Reading recent Windows attack logs", 10));
            foreach (var record in ReadRecentWindowsEvents("Security", fromUtc, SecurityEventIds, cancellationToken))
            {
                analyzer.Observe(record, context.MachineName);
                records++;
            }
            sourceCount++;

            foreach (var record in ReadRecentWindowsEvents("System", fromUtc, SystemEventIds, cancellationToken))
            {
                analyzer.Observe(record, context.MachineName);
                records++;
            }
            sourceCount++;

            foreach (var record in ReadRecentWindowsEvents("Microsoft-Windows-Sysmon/Operational", fromUtc, SysmonEventIds, cancellationToken))
            {
                analyzer.Observe(record, context.MachineName);
                records++;
            }
            sourceCount++;

            progress.Report(new ProgressUpdate(Metadata.Id, "Reading recent IIS logs", 55));
            var iisRecords = await ReadRecentIisRecordsAsync(fromUtc, analyzer, context.MachineName, cancellationToken)
                .ConfigureAwait(false);
            records += iisRecords;
            sourceCount += iisRecords > 0 ? 1 : 0;

            progress.Report(new ProgressUpdate(Metadata.Id, "Checking current TCP connections", 80));
            foreach (var f in BuildTcpSnapshotFindings(context.MachineName))
            {
                findings.Add(f);
            }

            foreach (var f in analyzer.BuildFindings(context.MachineName))
            {
                findings.Add(f);
            }

            if (findings.Count == 0)
            {
                findings.Add(Finding.Create(
                    id: "SRV-ATTACK-MONITOR-OK",
                    title: $"No high-confidence online server attack detected in last {lookbackMinutes} minutes",
                    severity: Severity.Info,
                    category: "server-attack.summary",
                    asset: context.MachineName,
                    evidence: $"Processed {records} recent records from {sourceCount} source group(s).",
                    remediation: "No immediate action from this module. Keep Sysmon/IIS/Security logging enabled for stronger detection.",
                    references: Array.Empty<string>()));
            }

            var snapshot = new ServerAttackMonitorSnapshot(
                LookbackMinutes: lookbackMinutes,
                RecordsProcessed: records,
                FindingsCount: findings.OfType<Finding>().Count(f => f.Severity >= Severity.High));
            context.SetShared(SharedSnapshotKey, snapshot);

            progress.Report(new ProgressUpdate(Metadata.Id, "Done", 100,
                $"{records} records, {findings.Count} finding(s)"));

            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            };
        }
        catch (OperationCanceledException)
        {
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = "Cancelled.",
                Findings = findings
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Server attack monitor failed");
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = ex.Message,
                Findings = findings
            };
        }
    }

    private async Task<int> ReadRecentIisRecordsAsync(
        DateTimeOffset fromUtc,
        ServerAttackAnalyzer analyzer,
        string asset,
        CancellationToken ct)
    {
        var iisRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System).Replace("\\System32", "", StringComparison.OrdinalIgnoreCase),
            "inetpub", "logs", "LogFiles");
        if (!Directory.Exists(iisRoot))
        {
            iisRoot = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "inetpub", "logs", "LogFiles");
        }
        if (!Directory.Exists(iisRoot))
        {
            return 0;
        }

        var parser = _parsers.OfType<IisW3cLogParser>().FirstOrDefault() ?? new IisW3cLogParser();
        int count = 0;
        var files = Directory.EnumerateFiles(iisRoot, "*.log", SearchOption.AllDirectories)
            .Where(p =>
            {
                try { return File.GetLastWriteTimeUtc(p) >= fromUtc.UtcDateTime.AddHours(-1); }
                catch { return false; }
            })
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .Take(200);

        foreach (var path in files)
        {
            ct.ThrowIfCancellationRequested();
            var raw = new RawLogFile(
                LocalPath: path,
                OriginalPath: path,
                OsHint: "windows",
                SizeBytes: new FileInfo(path).Length,
                Sha256: string.Empty);
            if (!parser.CanHandle(raw))
            {
                continue;
            }

            await foreach (var record in parser.ParseAsync(raw, ct).ConfigureAwait(false))
            {
                if (record.Timestamp < fromUtc)
                {
                    continue;
                }
                analyzer.Observe(record, asset);
                count++;
            }
        }

        return count;
    }

    private static IEnumerable<LogRecord> ReadRecentWindowsEvents(
        string channel,
        DateTimeOffset fromUtc,
        IReadOnlyList<int> eventIds,
        CancellationToken ct)
    {
        if (eventIds.Count == 0)
        {
            yield break;
        }

        var ms = Math.Max(1, (long)(DateTimeOffset.UtcNow - fromUtc).TotalMilliseconds);
        var idQuery = string.Join(" or ", eventIds.Select(id => $"EventID={id.ToString(CultureInfo.InvariantCulture)}"));
        var queryText = $"*[System[({idQuery}) and TimeCreated[timediff(@SystemTime) <= {ms.ToString(CultureInfo.InvariantCulture)}]]]";

        EventLogReader? reader = null;
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, queryText)
            {
                ReverseDirection = false
            };
            reader = new EventLogReader(query);
        }
        catch
        {
            yield break;
        }

        using (reader)
        {
            int read = 0;
            while (read++ < MaxEventRecordsPerChannel)
            {
                ct.ThrowIfCancellationRequested();
                EventRecord? evt;
                try { evt = reader.ReadEvent(); }
                catch { yield break; }
                if (evt is null) { yield break; }

                using (evt)
                {
                    var ts = new DateTimeOffset((evt.TimeCreated ?? DateTime.UtcNow).ToUniversalTime(), TimeSpan.Zero);
                    if (ts < fromUtc)
                    {
                        continue;
                    }

                    var kind = ResolveKind(evt.ProviderName ?? string.Empty, evt.Id);
                    if (kind is null)
                    {
                        continue;
                    }

                    yield return new LogRecord
                    {
                        Timestamp = ts,
                        SourceFile = "EventLog://" + channel,
                        SourceOffset = evt.RecordId ?? 0,
                        Os = "windows",
                        RawLine = TryFormatDescription(evt),
                        EventKind = kind,
                        Fields = ExtractFields(evt),
                        NativeLevel = evt.Level
                    };
                }
            }
        }
    }

    private static IReadOnlyList<Finding> BuildTcpSnapshotFindings(string asset)
    {
        var rows = EnumerateTcpRows().ToList();
        var inbound = rows
            .Where(r => r.State == TcpStateEstablished
                        && r.LocalPort > 0
                        && r.RemotePort > 0
                        && !IsLoopback(r.RemoteAddress)
                        && !r.RemoteAddress.Equals(r.LocalAddress)
                        && IsServerSensitivePort(r.LocalPort))
            .ToList();
        if (inbound.Count == 0)
        {
            return Array.Empty<Finding>();
        }

        var findings = new List<Finding>();
        foreach (var group in inbound.GroupBy(r => r.LocalPort).OrderBy(g => g.Key))
        {
            var remotes = group.Select(r => r.RemoteAddress.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var publicRemotes = remotes.Where(IsPublicIp).ToList();
            bool adminPort = IsAdminPort(group.Key);
            bool manySources = remotes.Count >= 20 || publicRemotes.Count >= 5;
            if (!adminPort && !manySources)
            {
                continue;
            }

            var severity = adminPort && publicRemotes.Count > 0 || manySources ? Severity.High : Severity.Medium;
            var samples = group.Take(10).Select(r => $"{r.RemoteAddress}:{r.RemotePort} -> {r.LocalAddress}:{r.LocalPort}");
            findings.Add(Finding.Create(
                id: $"SRV-TCP-{group.Key.ToString(CultureInfo.InvariantCulture)}",
                title: $"Current inbound TCP activity on sensitive port {group.Key}",
                severity: severity,
                category: "server-attack.live-connections",
                asset: asset,
                evidence:
                    $"Established connections={group.Count()}, distinct remote IPs={remotes.Count}, public remote IPs={publicRemotes.Count}.\n"
                    + "Samples:\n" + string.Join("\n", samples),
                remediation:
                    "Verify whether this service should be reachable. For RDP/SMB/WinRM/database ports, restrict source IPs at firewall/VPN and check authentication logs.",
                references: TcpReferences));
        }

        return findings;
    }

    private static string? ResolveKind(string provider, int eventId)
    {
        if (provider.StartsWith("Microsoft-Windows-Sysmon", StringComparison.OrdinalIgnoreCase))
        {
            return eventId switch
            {
                1 => "sysmon.process",
                3 => "sysmon.network",
                8 => "sysmon.createremotethread",
                10 => "sysmon.processaccess",
                17 => "sysmon.pipecreate",
                18 => "sysmon.pipeconnect",
                19 => "sysmon.wmifilter",
                20 => "sysmon.wmiconsumer",
                21 => "sysmon.wmibinding",
                _ => null
            };
        }

        return eventId switch
        {
            4624 => "logon.success",
            4625 => "logon.failed",
            4648 => "logon.explicit",
            4688 => "process.created",
            4697 => "service.installed",
            4698 => "task.created",
            4720 => "account.created",
            4732 => "group.memberadded",
            7045 => "service.installed",
            1102 => "log.cleared",
            _ => null
        };
    }

    private static Dictionary<string, string> ExtractFields(EventRecord evt)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["EventId"] = evt.Id.ToString(CultureInfo.InvariantCulture),
            ["Provider"] = evt.ProviderName ?? string.Empty,
            ["Channel"] = evt.LogName ?? string.Empty
        };

        try
        {
            ParseEventDataXml(evt.ToXml(), dict);
        }
        catch
        {
            // Best effort; the raw event description is still included.
        }

        return dict;
    }

    private static void ParseEventDataXml(string xml, Dictionary<string, string> dict)
    {
        int i = 0;
        while (i < xml.Length)
        {
            int tagStart = xml.IndexOf("<Data Name=\"", i, StringComparison.Ordinal);
            if (tagStart < 0) { break; }
            int nameStart = tagStart + "<Data Name=\"".Length;
            int nameEnd = xml.IndexOf('"', nameStart);
            if (nameEnd < 0) { break; }
            int valStart = xml.IndexOf('>', nameEnd) + 1;
            int valEnd = xml.IndexOf("</Data>", valStart, StringComparison.Ordinal);
            if (valStart <= 0 || valEnd < 0) { break; }
            var name = xml[nameStart..nameEnd];
            var value = WebUtility.HtmlDecode(xml[valStart..valEnd]);
            dict[name] = value;
            i = valEnd + 7;
        }
    }

    private static string TryFormatDescription(EventRecord evt)
    {
        try { return evt.FormatDescription() ?? $"EventID={evt.Id}"; }
        catch { return $"EventID={evt.Id}"; }
    }

    private static int ResolveLookbackMinutes(ScanContext context)
    {
        if (context.TryGetOption(OptionLookbackMinutesKey, out var raw)
            && int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var minutes))
        {
            return Math.Clamp(minutes, 15, 10080);
        }
        return DefaultLookbackMinutes;
    }

    private static IEnumerable<TcpRow> EnumerateTcpRows()
    {
        int bufLen = 0;
        uint err = GetExtendedTcpTable(IntPtr.Zero, ref bufLen, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (err != 0 && err != ERROR_INSUFFICIENT_BUFFER)
        {
            yield break;
        }

        IntPtr buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            err = GetExtendedTcpTable(buf, ref bufLen, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (err != 0)
            {
                yield break;
            }

            int numEntries = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            IntPtr rowPtr = IntPtr.Add(buf, 4);
            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                yield return new TcpRow(
                    State: row.dwState,
                    LocalAddress: new IPAddress(row.dwLocalAddr),
                    LocalPort: NtohsPort(row.dwLocalPort),
                    RemoteAddress: new IPAddress(row.dwRemoteAddr),
                    RemotePort: NtohsPort(row.dwRemotePort));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static bool IsServerSensitivePort(int port) =>
        port is 21 or 22 or 23 or 25 or 80 or 135 or 139 or 443 or 445
            or 1433 or 1521 or 3306 or 3389 or 5432 or 5900 or 5985 or 5986
            or 6379 or 8080 or 8443 or 9200 or 27017;

    private static bool IsAdminPort(int port) =>
        port is 21 or 22 or 23 or 135 or 139 or 445 or 1433 or 1521 or 3306
            or 3389 or 5432 or 5900 or 5985 or 5986 or 6379 or 9200 or 27017;

    private static bool IsPublicIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
        {
            return false;
        }
        var b = addr.GetAddressBytes();
        if (b.Length != 4) { return false; }
        if (b[0] == 10 || b[0] == 127) { return false; }
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) { return false; }
        if (b[0] == 192 && b[1] == 168) { return false; }
        if (b[0] == 169 && b[1] == 254) { return false; }
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) { return false; }
        if (b[0] >= 224) { return false; }
        return true;
    }

    private static bool IsLoopback(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        return b.Length == 4 && b[0] == 127;
    }

    private static int NtohsPort(uint raw) =>
        ((int)(raw & 0xFF) << 8) | (int)((raw >> 8) & 0xFF);

    private static readonly int[] SecurityEventIds =
    {
        4624, 4625, 4648, 4688, 4697, 4698, 4720, 4732, 1102
    };

    private static readonly int[] SystemEventIds =
    {
        7045
    };

    private static readonly int[] SysmonEventIds =
    {
        1, 3, 8, 10, 17, 18, 19, 20, 21
    };

    private static readonly string[] TcpReferences =
    {
        "MITRE ATT&CK T1021 - Remote Services",
        "MITRE ATT&CK T1046 - Network Service Discovery"
    };

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint TcpStateEstablished = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    private sealed record TcpRow(
        uint State,
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort);
}

public sealed record ServerAttackMonitorSnapshot(
    int LookbackMinutes,
    int RecordsProcessed,
    int FindingsCount);
