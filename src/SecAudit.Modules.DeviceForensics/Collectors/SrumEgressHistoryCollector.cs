using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Isam.Esent.Interop;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Reconstructs per-application network egress totals over the last ~30 days from the
/// Windows <b>SRUM</b> (System Resource Usage Monitor) database
/// <c>C:\Windows\System32\sru\SRUDB.dat</c> — an ESE/JET database the OS keeps for the
/// Settings → Battery / Data usage UI. SRUM is enabled by default on Win10/11; no audit
/// policy needs to be turned on. Retention is typically 30–60 days.
///
/// <para>
/// The reason this collector exists: SecAudit's existing <see cref="InternetEgressDetector"/>
/// only sees the snapshot at scan time (live <c>GetExtendedTcpTable</c>). When the SOC asks
/// "did app X reach the Internet last Tuesday at 3am?" only persistent telemetry can answer.
/// Without WFP audit policy enabled (Security log 5156), SRUM is the only built-in source.
/// </para>
///
/// <para>
/// Reading the database is non-trivial:
/// <list type="number">
///   <item>The DB is exclusively locked by the <b>DPS</b> (Diagnostic Policy Service)
///         while Windows is running, so even Admin can't open it directly.</item>
///   <item>We use <c>esentutl.exe /y /vss</c> to ask Windows to make a VSS snapshot copy
///         to <c>%LOCALAPPDATA%\SecAudit\srum-snapshot\SRUDB-{guid}.dat</c>. This requires
///         the Volume Shadow Copy Service (VSS) to be available — it is, by default.</item>
///   <item>We then open the snapshot read-only via <see cref="ManagedEsent"/> and walk the
///         <c>{973F5D5C-1D90-4944-BE8E-24B94231A174}</c> Network Data Usage table.</item>
///   <item>Per-record <c>AppId</c> is a small integer FK into <c>SruDbIdMapTable</c>, where
///         the mapping is stored as a UTF-16 LE blob — the value is either an SID prefix +
///         path, or a Modern App package full name. We resolve it to a friendly label.</item>
///   <item>Aggregate by app, sum bytes-sent + bytes-received, return the top N over the
///         caller's window (default 30 days).</item>
///   <item>Always delete the snapshot on the way out. We never leave a SRUM copy behind
///         because it contains user behaviour history that should not persist outside the
///         OS's own retention policy.</item>
/// </list>
/// </para>
///
/// <para>
/// Limitations the SOC operator must understand:
/// <list type="bullet">
///   <item>SRUM does NOT distinguish public-internet vs LAN bytes. We report total network
///         bytes per app. Combined with <see cref="InternetEgressDetector"/>'s live snapshot
///         the operator can correlate "this app moved 12 GB last month" with "this app is
///         still calling 8.8.8.8 right now".</item>
///   <item>SRUM tracks bytes per <i>interface</i> too, but we don't surface the interface
///         dimension in this MVP — it would explode the row count for marginal value.</item>
///   <item>If VSS is disabled (rare on production but happens on hardened images) the
///         snapshot fails. We then return an empty result with a status enum so the caller
///         can surface a "SRUM not available" finding instead of silently dropping data.</item>
/// </list>
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SrumEgressHistoryCollector
{
    /// <summary>Default lookback window in days when caller doesn't override.</summary>
    private const int DefaultDaysBack = 30;

    private const string SrumPath = @"C:\Windows\System32\sru\SRUDB.dat";
    /// <summary>
    /// Network Data Usage table GUID. Documented in MSDN "SRUM database" page and in the
    /// DFIR community for years. Other tables in SRUDB.dat (Application Resource Usage,
    /// Push Notification, etc.) are not relevant for egress reporting.
    /// </summary>
    private const string NetworkUsageTable = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";

    private readonly ILogger<SrumEgressHistoryCollector> _logger;

    public SrumEgressHistoryCollector(ILogger<SrumEgressHistoryCollector> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Snapshot SRUM, parse it, return one record per app aggregated over the last
    /// <paramref name="daysBack"/> days. Never throws — on any failure (no admin, VSS
    /// unavailable, ESE corrupted) returns a result whose <see cref="SrumEgressHistoryResult.Status"/>
    /// describes why and whose <see cref="SrumEgressHistoryResult.PerApp"/> is empty.
    /// </summary>
    public SrumEgressHistoryResult Collect(int daysBack = DefaultDaysBack)
    {
        if (!IsAdministrator())
        {
            _logger.LogDebug("SRUM read requires Administrator");
            return SrumEgressHistoryResult.Failed(
                "Cần quyền Administrator để đọc SRUM (chạy SecAudit dưới quyền admin).");
        }

        // Snapshot the locked DB to a temp path. esentutl is part of every Windows install.
        string snapshotDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAudit", "srum-snapshot");
        Directory.CreateDirectory(snapshotDir);
        string snapshotPath = Path.Combine(snapshotDir, $"SRUDB-{Guid.NewGuid():N}.dat");

        try
        {
            var copyOk = TryVssCopy(SrumPath, snapshotPath, out var copyErr);
            if (!copyOk)
            {
                return SrumEgressHistoryResult.Failed(
                    $"Không thể snapshot SRUDB.dat (esentutl /y /vss): {copyErr}");
            }
            if (!File.Exists(snapshotPath))
            {
                return SrumEgressHistoryResult.Failed(
                    "esentutl báo thành công nhưng không tạo được file snapshot.");
            }

            try
            {
                var (perApp, daysCovered) = ReadSrumTable(snapshotPath, daysBack);
                return SrumEgressHistoryResult.Ok(perApp, daysCovered);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse SRUM snapshot");
                return SrumEgressHistoryResult.Failed(
                    $"Snapshot OK nhưng đọc ESE thất bại: {ex.GetType().Name} {ex.Message}");
            }
        }
        finally
        {
            // Always cleanup — SRUM data is sensitive (per-app browsing history proxy).
            TryDelete(snapshotPath);
            // ESE log files travel with the snapshot — clean those too.
            foreach (var stray in Directory.EnumerateFiles(snapshotDir,
                Path.GetFileNameWithoutExtension(snapshotPath) + "*"))
            {
                TryDelete(stray);
            }
        }
    }

    /// <summary>
    /// Run <c>esentutl.exe /y /vss "src" /d "dst"</c> to take a Volume Shadow Copy snapshot
    /// of the locked SRUM database. Returns the exit code 0 on success; otherwise captures
    /// stderr/stdout into <paramref name="error"/> for diagnostics.
    /// </summary>
    private static bool TryVssCopy(string source, string destination, out string error)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "esentutl.exe",
            // /y = copy mode; /vss = use VSS for locked-file copy; /d = destination.
            // Quote both paths so spaces (none here, but defensive) don't break.
            Arguments = $"/y \"{source}\" /vss /d \"{destination}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        try
        {
            using var p = Process.Start(psi);
            if (p is null)
            {
                error = "ProcessStart(esentutl.exe) returned null.";
                return false;
            }
            // VSS snapshot can take 10-30s on a busy box.
            if (!p.WaitForExit(60_000))
            {
                try { p.Kill(true); } catch { }
                error = "esentutl /y /vss timed out after 60s.";
                return false;
            }
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            if (p.ExitCode != 0)
            {
                error = $"exit={p.ExitCode}; stdout={stdout.Trim()}; stderr={stderr.Trim()}";
                return false;
            }
            error = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Open the SRUM snapshot read-only via JET, walk the Network Data Usage table, build
    /// the AppId → bytes-sent + bytes-recv aggregate, then resolve AppId via the
    /// <c>SruDbIdMapTable</c> to a friendly app label. Returns one record per distinct app.
    /// </summary>
    private static (List<SrumEgressPerApp> Records, int DaysCovered) ReadSrumTable(string snapshotPath, int daysBack)
    {
        var cutoff = DateTime.UtcNow.AddDays(-daysBack);

        // Build LUID → "is the interface Internet-facing?" map ONCE before the table
        // walk — checked per-row but the underlying NetworkInterface enumeration is
        // expensive. An interface counts as Internet-facing when its IPv4 properties
        // carry at least one non-zero default gateway entry.
        var luidIsInternet = BuildLuidInternetMap();

        // Aggregate buffers keyed on AppId (int) — typical SRUM has ~50-200 distinct AppIds.
        // Two parallel dictionaries: Internet-facing interface bytes vs LAN-only.
        var sentInetByApp = new Dictionary<int, ulong>();
        var recvInetByApp = new Dictionary<int, ulong>();
        var sentLanByApp = new Dictionary<int, ulong>();
        var recvLanByApp = new Dictionary<int, ulong>();
        var firstSeenByApp = new Dictionary<int, DateTime>();
        var lastSeenByApp = new Dictionary<int, DateTime>();

        using (var instance = new Instance($"secaudit-srum-{Guid.NewGuid():N}"))
        {
            // Recovery=Off because we are reading a snapshot copy with no associated logs.
            instance.Parameters.Recovery = false;
            instance.Parameters.CircularLog = true;
            // Direct snapshot access — ESE wants a TempPath even read-only.
            instance.Parameters.TempDirectory = Path.GetDirectoryName(snapshotPath)!;
            instance.Parameters.SystemDirectory = Path.GetDirectoryName(snapshotPath)!;
            instance.Parameters.LogFileDirectory = Path.GetDirectoryName(snapshotPath)!;
            instance.Init();

            using var session = new Session(instance);
            Api.JetAttachDatabase(session, snapshotPath, AttachDatabaseGrbit.ReadOnly);
            Api.JetOpenDatabase(session, snapshotPath, null, out JET_DBID dbid, OpenDatabaseGrbit.ReadOnly);

            // Walk the network table.
            DateTime tableEarliest = DateTime.MaxValue, tableLatest = DateTime.MinValue;
            using (var table = new Table(session, dbid, NetworkUsageTable, OpenTableGrbit.ReadOnly))
            {
                var cols = Api.GetColumnDictionary(session, table);
                if (!cols.TryGetValue("AppId", out var appIdCol)
                    || !cols.TryGetValue("BytesSent", out var sentCol)
                    || !cols.TryGetValue("BytesRecvd", out var recvCol)
                    || !cols.TryGetValue("TimeStamp", out var tsCol))
                {
                    throw new InvalidOperationException("SRUM Network table schema unexpected (missing columns).");
                }
                // InterfaceLuid is optional — present on Win10 1809+. When absent we
                // attribute every byte to "Internet" to stay safe (over-warn is better
                // than under-warn for an audit tool).
                bool hasLuidCol = cols.TryGetValue("InterfaceLuid", out var luidCol);

                if (Api.TryMoveFirst(session, table))
                {
                    do
                    {
                        var ts = Api.RetrieveColumnAsDateTime(session, table, tsCol);
                        if (ts.HasValue)
                        {
                            if (ts.Value < tableEarliest) { tableEarliest = ts.Value; }
                            if (ts.Value > tableLatest) { tableLatest = ts.Value; }
                            if (ts.Value < cutoff) { continue; }
                        }
                        var appId = Api.RetrieveColumnAsInt32(session, table, appIdCol) ?? 0;
                        if (appId == 0) { continue; }
                        var bytesSent = (ulong?)Api.RetrieveColumnAsInt64(session, table, sentCol) ?? 0;
                        var bytesRecv = (ulong?)Api.RetrieveColumnAsInt64(session, table, recvCol) ?? 0;

                        // Decide bucket: Internet vs LAN based on the per-row interface.
                        bool isInternet = true; // safe default when LUID column missing
                        if (hasLuidCol)
                        {
                            var luidRaw = Api.RetrieveColumnAsInt64(session, table, luidCol);
                            if (luidRaw.HasValue)
                            {
                                var luid = (ulong)luidRaw.Value;
                                if (luidIsInternet.TryGetValue(luid, out var v))
                                {
                                    isInternet = v;
                                }
                                // Unknown LUID (interface removed since SRUM recorded it):
                                // keep default isInternet=true.
                            }
                        }
                        if (isInternet)
                        {
                            sentInetByApp.TryGetValue(appId, out var s); sentInetByApp[appId] = s + bytesSent;
                            recvInetByApp.TryGetValue(appId, out var r); recvInetByApp[appId] = r + bytesRecv;
                        }
                        else
                        {
                            sentLanByApp.TryGetValue(appId, out var s); sentLanByApp[appId] = s + bytesSent;
                            recvLanByApp.TryGetValue(appId, out var r); recvLanByApp[appId] = r + bytesRecv;
                        }
                        if (ts.HasValue)
                        {
                            if (!firstSeenByApp.TryGetValue(appId, out var f) || ts.Value < f)
                            {
                                firstSeenByApp[appId] = ts.Value;
                            }
                            if (!lastSeenByApp.TryGetValue(appId, out var l) || ts.Value > l)
                            {
                                lastSeenByApp[appId] = ts.Value;
                            }
                        }
                    } while (Api.TryMoveNext(session, table));
                }
            }

            // Resolve AppId → friendly name via SruDbIdMapTable. Take union of all
            // AppIds (Internet OR LAN) so a LAN-only app still gets a label.
            var allAppIds = new HashSet<int>(sentInetByApp.Keys);
            allAppIds.UnionWith(sentLanByApp.Keys);
            var idToName = ResolveAppIds(session, dbid, allAppIds);

            var results = new List<SrumEgressPerApp>(allAppIds.Count);
            foreach (var id in allAppIds)
            {
                sentInetByApp.TryGetValue(id, out var sentInet);
                recvInetByApp.TryGetValue(id, out var recvInet);
                sentLanByApp.TryGetValue(id, out var sentLan);
                recvLanByApp.TryGetValue(id, out var recvLan);
                idToName.TryGetValue(id, out var name);
                firstSeenByApp.TryGetValue(id, out var first);
                lastSeenByApp.TryGetValue(id, out var last);
                results.Add(new SrumEgressPerApp(
                    AppLabel: name ?? $"(AppId {id})",
                    BytesSentInternet: sentInet,
                    BytesReceivedInternet: recvInet,
                    BytesSentLan: sentLan,
                    BytesReceivedLan: recvLan,
                    FirstSeenUtc: first == default ? null : first,
                    LastSeenUtc: last == default ? null : last));
            }

            int daysCovered = (tableLatest > tableEarliest)
                ? Math.Max(1, (int)Math.Round((tableLatest - tableEarliest).TotalDays))
                : 0;
            // Sort: Internet-talkers first by Internet bytes desc, then LAN-only by LAN bytes desc.
            return (results
                .OrderByDescending(r => r.HasInternetTraffic)
                .ThenByDescending(r => r.TotalInternetBytes + r.TotalLanBytes)
                .ToList(), daysCovered);
        }
    }

    /// <summary>
    /// Build a lookup table from Windows interface LUID to a boolean "this interface has
    /// at least one IPv4 default gateway, therefore packets sent on it leave the LAN".
    /// LUIDs come from <see cref="ConvertInterfaceIndexToLuid"/> — we walk every NIC
    /// reported by <see cref="NetworkInterface.GetAllNetworkInterfaces"/> and resolve
    /// its index to a LUID so SRUM rows (which carry only LUID) can be classified later.
    /// </summary>
    private static Dictionary<ulong, bool> BuildLuidInternetMap()
    {
        var map = new Dictionary<ulong, bool>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPInterfaceProperties? props;
                try { props = ni.GetIPProperties(); } catch { continue; }
                int idx;
                try { idx = props.GetIPv4Properties()?.Index ?? -1; } catch { continue; }
                if (idx < 0) { continue; }

                if (ConvertInterfaceIndexToLuid((uint)idx, out var luid) != 0) { continue; }

                bool hasGateway = false;
                foreach (var gw in props.GatewayAddresses)
                {
                    if (gw.Address.AddressFamily != AddressFamily.InterNetwork) { continue; }
                    if (gw.Address.Equals(System.Net.IPAddress.Any)) { continue; }
                    hasGateway = true;
                    break;
                }
                map[luid] = hasGateway;
            }
        }
        catch
        {
            // Network enumeration can fail under restricted token — fall back to empty
            // map; caller defaults to isInternet=true so we over-warn rather than miss.
        }
        return map;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int ConvertInterfaceIndexToLuid(uint interfaceIndex, out ulong interfaceLuid);

    /// <summary>
    /// Build AppId → friendly name dictionary from <c>SruDbIdMapTable</c>. Each row carries
    /// a binary <c>IdBlob</c> which is normally a UTF-16 LE string (sometimes prefixed with
    /// service/SID metadata). We do best-effort decoding — anything unreadable is replaced
    /// with the bare AppId number so the report is never blank.
    /// </summary>
    private static Dictionary<int, string> ResolveAppIds(Session session, JET_DBID dbid, IEnumerable<int> wanted)
    {
        var map = new Dictionary<int, string>();
        var wantedSet = new HashSet<int>(wanted);
        try
        {
            using var table = new Table(session, dbid, "SruDbIdMapTable", OpenTableGrbit.ReadOnly);
            var cols = Api.GetColumnDictionary(session, table);
            if (!cols.TryGetValue("IdIndex", out var idCol)
                || !cols.TryGetValue("IdBlob", out var blobCol))
            {
                return map;
            }
            if (Api.TryMoveFirst(session, table))
            {
                do
                {
                    var id = Api.RetrieveColumnAsInt32(session, table, idCol);
                    if (id is null || !wantedSet.Contains(id.Value)) { continue; }
                    var blob = Api.RetrieveColumn(session, table, blobCol);
                    map[id.Value] = DecodeIdBlob(blob);
                } while (Api.TryMoveNext(session, table));
            }
        }
        catch
        {
            // Map table missing or unreadable — leave dictionary empty; caller falls back
            // to "(AppId N)" labels.
        }
        return map;
    }

    /// <summary>
    /// SRUM stores app identifiers as wide-char (UTF-16 LE) strings. Many entries are bare
    /// path-like strings; some are prefixed with a SID + "!" or service name. We trim
    /// non-printable trailing bytes and shorten very long Modern App package names.
    /// </summary>
    internal static string DecodeIdBlob(byte[]? blob)
    {
        if (blob is null || blob.Length == 0) { return "(unknown)"; }
        // Try UTF-16 LE first (the dominant SRUM encoding).
        var s = System.Text.Encoding.Unicode.GetString(blob).TrimEnd('\0').Trim();
        if (string.IsNullOrWhiteSpace(s) || s.Any(c => c < 0x20 && c != '\t'))
        {
            // Fall back to ASCII, last resort.
            s = System.Text.Encoding.ASCII.GetString(blob).TrimEnd('\0').Trim();
        }
        // Shorten common formats:
        //   "S-1-5-21-...!C:\Path\app.exe" → "C:\Path\app.exe"
        //   Modern Apps "S-1-15-2-...!Microsoft.WindowsStore_8wekyb3d8bbwe" → "Microsoft.WindowsStore"
        var bang = s.IndexOf('!');
        if (bang >= 0 && bang < s.Length - 1)
        {
            s = s[(bang + 1)..];
        }
        // For Modern Apps, strip the publisher hash trailer for readability.
        var underscore = s.IndexOf('_');
        if (underscore > 0 && !s.Contains('\\') && !s.Contains('/'))
        {
            s = s[..underscore];
        }
        return s.Length > 120 ? s[..120] + "..." : s;
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private void TryDelete(string path)
    {
        try { if (File.Exists(path)) { File.Delete(path); } }
        catch (Exception ex) { _logger.LogTrace(ex, "Failed to delete temp file {Path}", path); }
    }
}
