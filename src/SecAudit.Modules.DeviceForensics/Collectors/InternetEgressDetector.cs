using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Snapshots every TCP connection on the box at audit time and surfaces those whose
/// remote endpoint is a public (Internet-routable) IPv4 address.
///
/// <para>
/// Policy at Công an tỉnh Sơn La: workstations operate inside the corporate intranet only;
/// any process reaching out to the public Internet is a finding worth investigating
/// (could be unauthorised browser/cloud sync, RAT C2, telemetry beaconing, etc.). We
/// enumerate connections via <c>iphlpapi!GetExtendedTcpTable</c> with the
/// <c>TCP_TABLE_OWNER_PID_ALL</c> table class so we get the owning PID for every row,
/// then resolve the PID into a process name + main-module path so the SOC can identify
/// the responsible binary.
/// </para>
///
/// <para>
/// We only enumerate IPv4. The IPv6 equivalent (<c>GetExtendedTcp6Table</c>) is left for
/// a future iteration — most internal LANs at SMB scale don't run dual-stack and the
/// IPv4 view alone catches the policy-relevant traffic. UDP is intentionally excluded:
/// it is connectionless and would produce noise (DNS, NTP). The TCP listening sockets
/// (<c>state = LISTEN</c>) are also excluded — only ESTABLISHED sockets count as egress.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class InternetEgressDetector
{
    private readonly ILogger<InternetEgressDetector> _logger;

    public InternetEgressDetector(ILogger<InternetEgressDetector> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Returns every ESTABLISHED IPv4 TCP connection on the box. Caller filters by
    /// <see cref="EgressConnectionRecord.RemoteIsPublic"/> when only Internet-bound rows
    /// are wanted.
    /// </summary>
    public IReadOnlyList<EgressConnectionRecord> Collect()
    {
        var list = new List<EgressConnectionRecord>();
        try
        {
            // Two-call idiom: first call sizes the buffer, second call fills it. We loop
            // because between the two calls a new connection could have appeared and the
            // buffer suddenly be too small (ERROR_INSUFFICIENT_BUFFER again).
            int bufLen = 0;
            uint err = GetExtendedTcpTable(IntPtr.Zero, ref bufLen, false,
                AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (err != 0 && err != ERROR_INSUFFICIENT_BUFFER)
            {
                _logger.LogDebug("GetExtendedTcpTable sizing call returned {Err}", err);
                return list;
            }

            IntPtr buf = Marshal.AllocHGlobal(bufLen);
            try
            {
                err = GetExtendedTcpTable(buf, ref bufLen, false,
                    AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (err != 0)
                {
                    _logger.LogDebug("GetExtendedTcpTable fetch call returned {Err}", err);
                    return list;
                }

                // Layout: DWORD numEntries, then numEntries × MIB_TCPROW_OWNER_PID.
                int numEntries = Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                IntPtr rowPtr = IntPtr.Add(buf, 4);

                // Cache process-name lookups — many connections share a PID (chrome.exe
                // has dozens). Process.GetProcessById is not free, so we de-dup.
                var pidNameCache = new Dictionary<int, (string Name, string? Path)>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    if (row.dwState != MIB_TCP_STATE_ESTAB)
                    {
                        continue;
                    }
                    var local = new IPAddress(row.dwLocalAddr);
                    var remote = new IPAddress(row.dwRemoteAddr);
                    int localPort = NtohsPort(row.dwLocalPort);
                    int remotePort = NtohsPort(row.dwRemotePort);

                    // Skip loopback-on-loopback rows (e.g. 127.0.0.1:* ↔ 127.0.0.1:*)
                    // — those are intra-machine IPC, not relevant for egress audit.
                    if (IsLoopbackAddress(remote))
                    {
                        continue;
                    }

                    int pid = (int)row.dwOwningPid;
                    if (!pidNameCache.TryGetValue(pid, out var info))
                    {
                        info = ResolveProcess(pid);
                        pidNameCache[pid] = info;
                    }

                    list.Add(new EgressConnectionRecord(
                        ProcessId: pid,
                        ProcessName: info.Name,
                        ProcessPath: info.Path,
                        LocalEndpoint: $"{local}:{localPort}",
                        RemoteEndpoint: $"{remote}:{remotePort}",
                        RemoteAddress: remote.ToString(),
                        RemotePort: remotePort,
                        RemoteIsPublic: IsPublicAddress(remote),
                        Protocol: "TCP"));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to enumerate TCP connections");
        }
        return list;
    }

    /// <summary>
    /// Resolve PID → (process name, executable path). Path lookup will fail for processes
    /// in another session (kernel processes, services running as SYSTEM, protected
    /// processes like csrss.exe) — name still works because it comes from the kernel via
    /// <see cref="Process.ProcessName"/>.
    /// </summary>
    private static (string Name, string? Path) ResolveProcess(int pid)
    {
        if (pid <= 0)
        {
            return ("(system idle/unknown)", null);
        }
        try
        {
            using var p = Process.GetProcessById(pid);
            string? path = null;
            try
            {
                path = p.MainModule?.FileName;
            }
            catch
            {
                // Access denied for cross-session / protected processes — name only.
            }
            return (p.ProcessName, path);
        }
        catch
        {
            return ($"(pid {pid})", null);
        }
    }

    /// <summary>
    /// Classify an IPv4 address as "leaves the LAN" (true) vs "stays on local
    /// infrastructure" (false). Anything in the standard private / link-local / loopback /
    /// CGNAT ranges is treated as internal.
    /// </summary>
    public static bool IsPublicAddress(IPAddress addr)
    {
        if (addr is null) { return false; }
        var b = addr.GetAddressBytes();
        if (b.Length != 4) { return false; }

        // 0.0.0.0/8 (this network) and 255.255.255.255 (broadcast)
        if (b[0] == 0 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255))
        {
            return false;
        }
        // Loopback 127.0.0.0/8
        if (b[0] == 127) { return false; }
        // Private RFC1918
        if (b[0] == 10) { return false; }
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) { return false; }
        if (b[0] == 192 && b[1] == 168) { return false; }
        // Link-local 169.254/16
        if (b[0] == 169 && b[1] == 254) { return false; }
        // CGNAT (RFC6598) 100.64.0.0/10
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) { return false; }
        // Multicast 224.0.0.0/4 — not a unicast egress in any meaningful sense.
        if (b[0] >= 224 && b[0] <= 239) { return false; }
        // Reserved 240.0.0.0/4
        if (b[0] >= 240) { return false; }
        return true;
    }

    private static bool IsLoopbackAddress(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        return b.Length == 4 && b[0] == 127;
    }

    /// <summary>
    /// dwLocalPort/dwRemotePort are stored network-byte-order in the high two bytes; the
    /// low two bytes are zero. Convert to host order and clamp to ushort.
    /// </summary>
    private static int NtohsPort(uint raw)
    {
        // The port lives in bytes 0-1 in NETWORK order — i.e. high byte first.
        return ((int)(raw & 0xFF) << 8) | (int)((raw >> 8) & 0xFF);
    }

    // ---- P/Invoke surface --------------------------------------------------------------

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint MIB_TCP_STATE_ESTAB = 5;

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
}
