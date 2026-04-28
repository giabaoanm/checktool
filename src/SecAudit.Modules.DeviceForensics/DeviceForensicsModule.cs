using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Modules.DeviceForensics.Collectors;
using SecAudit.Modules.DeviceForensics.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.DeviceForensics;

/// <summary>
/// Phần 9 — "Lịch sử thiết bị &amp; mạng". Surfaces the persistent registry artefacts
/// the SOC operator needs to reconstruct user behaviour on a regulated workstation:
/// every USB stick ever inserted, every phone ever tethered, every Wi-Fi/Ethernet/VPN
/// network ever joined, and the current vs. policy-expected IP configuration.
///
/// <para>
/// Per the deployment policy at Công an tỉnh Sơn La:
/// <list type="bullet">
///   <item>Workstations are connected only to the internal LAN/WAN; joining external
///         Wi-Fi or mobile broadband is prohibited.</item>
///   <item>IP addresses are issued exclusively by the corporate DHCP server; users are
///         not authorised to set static IPs.</item>
///   <item>Removable storage and personal phones are restricted by policy — both leave
///         persistent registry traces even after being "ejected" or "forgotten".</item>
/// </list>
/// </para>
///
/// <para>
/// The module never writes to anything; remediation strings tell the admin where to
/// look in Settings or which group-policy lever to throw.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DeviceForensicsModule : IAuditModule
{
    /// <summary>
    /// Cross-module snapshot key — the report's "Phạm vi quét" picks this up so it can
    /// show denominators ("3/8 USB là phone-grade", "2/5 mạng đã ghi nhớ là Wi-Fi").
    /// </summary>
    public const string SharedSnapshotKey = "device-forensics.snapshot";

    /// <summary>
    /// Window (days) in which a recent registry edit on the Tcpip\Parameters\Interfaces\{guid}
    /// key is treated as an "IP plan change requires verification" event. Anything older is
    /// assumed to have been signed off long ago and surfaces as plain Info.
    /// </summary>
    private const int StaticIpChangeWindowDays = 30;

    private static readonly string[] RefUsb =
    {
        "https://docs.microsoft.com/windows-hardware/drivers/install/setupapi-text-logs"
    };
    private static readonly string[] RefPortable =
    {
        "https://docs.microsoft.com/windows/win32/wpd_sdk/wpd-application-programming-interface"
    };
    private static readonly string[] RefNetworkList =
    {
        "https://attack.mitre.org/techniques/T1016/"
    };
    private static readonly string[] RefStaticIp =
    {
        "https://docs.microsoft.com/windows-server/networking/technologies/dhcp/dhcp-top"
    };
    private static readonly string[] RefEgress =
    {
        "https://attack.mitre.org/techniques/T1071/",
        "https://attack.mitre.org/techniques/T1041/"
    };

    private readonly UsbStorageHistoryCollector _usb;
    private readonly PortableDeviceCollector _portable;
    private readonly NetworkProfileCollector _network;
    private readonly IpConfigCollector _ip;
    private readonly InternetEgressDetector _egress;
    private readonly DeviceConnectionEventCollector _connectionEvents;
    private readonly SrumEgressHistoryCollector _srum;
    private readonly IOfflineTarget _target;
    private readonly ILogger<DeviceForensicsModule> _logger;

    public DeviceForensicsModule(
        UsbStorageHistoryCollector usb,
        PortableDeviceCollector portable,
        NetworkProfileCollector network,
        IpConfigCollector ip,
        InternetEgressDetector egress,
        DeviceConnectionEventCollector connectionEvents,
        SrumEgressHistoryCollector srum,
        IOfflineTarget target,
        ILogger<DeviceForensicsModule> logger)
    {
        _usb = usb;
        _portable = portable;
        _network = network;
        _ip = ip;
        _egress = egress;
        _connectionEvents = connectionEvents;
        _srum = srum;
        _target = target;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "device-forensics",
        DisplayName: "Lịch sử thiết bị & mạng",
        Description: "Lịch sử USB, điện thoại, mạng đã kết nối và cấu hình IP — phát hiện thay đổi IP và kết nối ngoài chính sách.",
        Category: "Bề mặt tấn công",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: false,
        DisplayOrder: 90);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();
        var asset = context.MachineName;

        IReadOnlyList<UsbStorageRecord> usbs = Array.Empty<UsbStorageRecord>();
        IReadOnlyList<PortableDeviceRecord> portables = Array.Empty<PortableDeviceRecord>();
        IReadOnlyList<NetworkProfileRecord> nets = Array.Empty<NetworkProfileRecord>();
        IReadOnlyList<WifiProfileRecord> wifi = Array.Empty<WifiProfileRecord>();
        IReadOnlyList<InterfaceIpRecord> ifaces = Array.Empty<InterfaceIpRecord>();

        try
        {
            // 1) USB mass-storage history -------------------------------------------------
            // Compaction policy: ONE consolidated finding per logical group, evidence is a
            // multi-line bullet list. The report renders evidence with white-space:pre-wrap
            // so '\n' becomes a visible line break in HTML/PDF/DOCX.
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đọc lịch sử USB từ USBSTOR", 10));
            usbs = _usb.Collect();

            // Pre-fetch the per-serial connection-event timeline from
            // Microsoft-Windows-Partition/Diagnostic 1006 — answers "when ELSE was this
            // device plugged in, not just the most recent time?". Returns empty map if
            // the channel is missing or denied — gracefully degrades to DEVPKEY-only data.
            IReadOnlyDictionary<string, IReadOnlyList<DeviceConnectionEvent>> connHistoryBySerial;
            try
            {
                connHistoryBySerial = _connectionEvents.CollectMassStorageHistoryBySerial();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Connection-event collector failed; continuing without history timeline");
                connHistoryBySerial = new Dictionary<string, IReadOnlyList<DeviceConnectionEvent>>();
            }

            // ONE row aggregating EVERY USB device ever seen — bullet list per device with
            // lifecycle + connection-event summary inline.
            if (usbs.Count == 0)
            {
                findings.Add(Finding.Create(
                    id: "USB-HIST",
                    title: "Không phát hiện USB lưu trữ nào từng cắm vào máy",
                    severity: Severity.Info,
                    category: "Lịch sử thiết bị",
                    asset: asset,
                    evidence: "Khóa SYSTEM\\CurrentControlSet\\Enum\\USBSTOR rỗng.",
                    remediation: "Không cần xử lý.",
                    references: RefUsb));
            }
            else
            {
                var usbLines = new List<string>(usbs.Count);
                int totalConnFound = 0;
                foreach (var u in usbs)
                {
                    var label = !string.IsNullOrWhiteSpace(u.FriendlyName)
                        ? u.FriendlyName!
                        : $"{u.Vendor} {u.Product}".Trim();

                    // Look up event-log history for this serial (raw + normalised form).
                    IReadOnlyList<DeviceConnectionEvent>? history = null;
                    if (!connHistoryBySerial.TryGetValue(u.SerialNumber, out history))
                    {
                        connHistoryBySerial.TryGetValue(
                            DeviceConnectionEventCollector.NormaliseSerial(u.SerialNumber), out history);
                    }
                    history ??= Array.Empty<DeviceConnectionEvent>();
                    totalConnFound += history.Count;

                    var lifecycle = BuildLifecycleString(
                        u.FirstInstallUtc, u.LastArrivalUtc, u.LastRemovalUtc, u.InstallEventCount);

                    string historyFragment;
                    if (history.Count == 0)
                    {
                        historyFragment = "Event Log: không có sự kiện 1006 trong cửa sổ giữ log.";
                    }
                    else
                    {
                        var sample = history.TakeLast(8).Select(e => FormatDate(e.AtUtc));
                        var more = history.Count - 8;
                        var moreSuffix = more > 0 ? $" (+{more} lần cũ hơn)" : "";
                        historyFragment = $"Event Log: {history.Count} lần cắm — {string.Join(", ", sample)}{moreSuffix}.";
                    }

                    usbLines.Add(
                        $"• [{label}] Serial={u.SerialNumber}; Vendor={u.Vendor}; Product={u.Product}; Rev={u.Revision}\n"
                        + $"    {lifecycle}\n"
                        + $"    {historyFragment}");
                }

                var headline = totalConnFound > 0
                    ? $"Phát hiện {usbs.Count} USB lưu trữ — tổng {totalConnFound} lần cắm trong Event Log"
                    : $"Phát hiện {usbs.Count} USB lưu trữ — Event Log không còn dữ liệu lịch sử";

                findings.Add(Finding.Create(
                    id: "USB-HIST",
                    title: headline,
                    severity: Severity.Info,
                    category: "Lịch sử thiết bị",
                    asset: asset,
                    evidence: string.Join("\n", usbLines),
                    remediation:
                        "Đối chiếu danh sách trên với danh mục USB được cấp phép. Với serial lạ — xác minh "
                        + "với người dùng. Đối chiếu các thời điểm 'cắm gần nhất' / 'lần cắm Event Log' với "
                        + "giờ làm việc và nhật ký ra vào để phát hiện sử dụng ngoài giờ. "
                        + (totalConnFound == 0
                            ? "Để giữ lịch sử lâu hơn: 'wevtutil sl Microsoft-Windows-Partition/Diagnostic /ms:10485760' (nâng lên 10 MB). "
                            : "")
                        + "Cân nhắc bật chính sách 'Removable Storage Access' (gpedit) để chặn USB lạ.",
                    references: RefUsb));
            }

            // 2) Portable devices (phone/tablet/camera) — ONE consolidated row ------------
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đọc lịch sử thiết bị di động (MTP/PTP)", 30));
            portables = _portable.Collect();
            var phoneCount = portables.Count(p => p.LooksLikePhone);
            var otherCount = portables.Count - phoneCount;

            if (portables.Count == 0)
            {
                findings.Add(Finding.Create(
                    id: "PHN-HIST",
                    title: "Không phát hiện điện thoại/MTP nào từng kết nối",
                    severity: Severity.Info,
                    category: "Lịch sử thiết bị",
                    asset: asset,
                    evidence: "Khóa SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices rỗng.",
                    remediation: "Không cần xử lý.",
                    references: RefPortable));
            }
            else
            {
                var phoneLines = new List<string>();
                var otherLines = new List<string>();
                foreach (var p in portables)
                {
                    var lifecycle = BuildLifecycleString(
                        p.FirstInstallUtc, p.LastArrivalUtc, p.LastRemovalUtc, p.InstallEventCount);
                    var line = $"• [{p.FriendlyName}]\n    {lifecycle}\n    InstanceId={p.DeviceInstanceId}";
                    if (p.LooksLikePhone) { phoneLines.Add(line); } else { otherLines.Add(line); }
                }

                var sb = new System.Text.StringBuilder();
                if (phoneLines.Count > 0)
                {
                    sb.Append("Điện thoại / máy tính bảng:\n");
                    sb.Append(string.Join("\n", phoneLines));
                }
                if (otherLines.Count > 0)
                {
                    if (sb.Length > 0) { sb.Append("\n\n"); }
                    sb.Append("Thiết bị WPD khác (camera, máy in...):\n");
                    sb.Append(string.Join("\n", otherLines));
                }

                // Severity: Medium when at least one phone (policy violation), else Info.
                var sev = phoneCount > 0 ? Severity.Medium : Severity.Info;
                var headline = phoneCount > 0
                    ? $"Phát hiện {phoneCount} điện thoại/tablet và {otherCount} thiết bị WPD khác từng kết nối"
                    : $"Phát hiện {otherCount} thiết bị WPD (không có điện thoại/tablet)";

                findings.Add(Finding.Create(
                    id: "PHN-HIST",
                    title: headline,
                    severity: sev,
                    category: "Lịch sử thiết bị",
                    asset: asset,
                    evidence: sb.ToString(),
                    remediation: phoneCount > 0
                        ? "Chính sách thường cấm cắm điện thoại cá nhân vào máy trạm vì đây là kênh chuyển dữ liệu hai chiều. "
                          + "Xác minh từng thiết bị với người dùng; nếu không có lý do nghiệp vụ, bật Computer Configuration → "
                          + "Administrative Templates → System → Removable Storage Access → 'WPD Devices: Deny read/write access'."
                        : "Không có điện thoại/tablet — đối chiếu các thiết bị WPD còn lại (camera, máy in) với danh mục được cấp phép.",
                    references: RefPortable));
            }

            // 3) Network profiles — ONE consolidated row + ONE for weak Wi-Fi ------------
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đọc danh sách mạng đã từng kết nối", 55));
            nets = _network.CollectProfiles();

            // Bucket each profile so we can sort by severity (worst first) inside one cell.
            var profLines = new List<(Severity Sev, string Line)>();
            foreach (var n in nets)
            {
                var (sev, why) = ClassifyNetwork(n);
                if (sev is null) { continue; }
                var nameTypeLabel = NameTypeLabel(n.NameType);
                var lastConn = n.LastConnectedUtc is null ? "?" : FormatDate(n.LastConnectedUtc.Value);
                var firstConn = n.FirstConnectedUtc is null ? "?" : FormatDate(n.FirstConnectedUtc.Value);
                profLines.Add((sev.Value,
                    $"• [{sev.Value}] {n.ProfileName} — {nameTypeLabel}, {CategoryLabel(n.Category)}\n"
                    + $"    Source={n.Source}; Desc={n.Description ?? "?"}; GwMac={n.DefaultGatewayMac ?? "?"}\n"
                    + $"    FirstConn={firstConn} UTC; LastConn={lastConn} UTC\n"
                    + $"    Lý do gắn cờ: {why}"));
            }

            // NET-PROF — registry-based (NetworkList\Profiles). Carries dates + NameType
            // (Wi-Fi/Wired/Mobile/VPN). On some machines the key gets wiped (Windows reset,
            // 3rd-party cleaner) — in which case NET-WIFI below picks up the slack from
            // the Wlansvc XML store.
            if (profLines.Count == 0)
            {
                var emptyEvidence = nets.Count == 0
                    ? "Khóa registry NetworkList\\Profiles rỗng. Lưu ý: dữ liệu Wi-Fi có thể vẫn còn ở "
                      + "Wlansvc — xem finding NET-WIFI bên dưới."
                    : $"Tất cả {nets.Count} profile đều là mạng có dây/domain — phù hợp chính sách.";
                findings.Add(Finding.Create(
                    id: "NET-PROF",
                    title: $"NetworkList registry: {nets.Count} mạng — không có mạng nào ngoài chính sách",
                    severity: Severity.Info,
                    category: "Lịch sử mạng",
                    asset: asset,
                    evidence: emptyEvidence,
                    remediation: "Không cần xử lý.",
                    references: RefNetworkList));
            }
            else
            {
                var topSev = profLines.Max(x => x.Sev);
                var sortedLines = profLines
                    .OrderByDescending(x => x.Sev)
                    .Select(x => x.Line);
                findings.Add(Finding.Create(
                    id: "NET-PROF",
                    title: $"Đã ghi nhớ {profLines.Count} mạng ngoài chính sách (trong tổng {nets.Count} profile)",
                    severity: topSev,
                    category: "Lịch sử mạng",
                    asset: asset,
                    evidence: string.Join("\n", sortedLines),
                    remediation:
                        "Với mỗi profile trong danh sách: Settings → Network & Internet → 'Manage known networks' → "
                        + "'Forget'. Để xóa triệt để: xóa khóa HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                        + "NetworkList\\Profiles\\{guid} tương ứng.",
                    references: RefNetworkList));
            }

            // NET-WIFI-ADAPTER — every Wi-Fi card / USB Wi-Fi dongle ever attached.
            // Source: Wlansvc\Profiles\Interfaces\{ifGuid} folders + cross-ref with
            // HKLM\Network class registry to classify by bus type (PCI / USB / Virtual)
            // and pull friendly name even for uninstalled adapters.
            //
            // Important UX detail: a single physical Wi-Fi card often leaves multiple
            // {ifGuid} folders behind after driver-update / Windows-feature-update
            // cycles. Without grouping the operator sees "7 adapter từng gắn" when in
            // reality the machine only ever had one Intel AX210 — confusing. We
            // group by PnpInstanceID; each unique PnP device = 1 physical adapter
            // (its stale {ifGuid}s are noted as historical artefacts).
            var wifiAdapters = _network.CollectWifiAdapters();
            if (wifiAdapters.Count > 0)
            {
                EmitWifiAdapterFinding(findings, asset, wifiAdapters);
            }

            // NET-WIFI — Wlansvc XML store (separate, more durable than NetworkList registry).
            // Per chính sách Sơn La "máy trạm chỉ dùng mạng có dây nội bộ", BẤT KỲ Wi-Fi
            // profile nào còn lưu trữ đều là vi phạm — không lọc theo độ mạnh mã hóa nữa.
            // Severity: High nếu có cấu hình yếu (Open/WEP/WPA-PSK); Medium nếu mã hóa
            // mạnh (WPA2/WPA3) nhưng vẫn vi phạm chính sách "không Wi-Fi".
            wifi = _network.CollectWifi();
            if (wifi.Count > 0)
            {
                var weakNames = wifi.Where(IsWeakWifi).Select(w => w.ProfileName).ToList();
                var sev = weakNames.Count > 0 ? Severity.High : Severity.Medium;
                var lines = wifi
                    .OrderBy(w => w.ProfileName, StringComparer.OrdinalIgnoreCase)
                    .Select(w =>
                    {
                        var weakTag = IsWeakWifi(w) ? " [YẾU]" : "";
                        return $"• {w.ProfileName}{weakTag} — Auth={w.AuthMethod}; Enc={w.EncryptionMethod}; Mode={w.ConnectionMode}";
                    });
                var headline = weakNames.Count > 0
                    ? $"Có {wifi.Count} Wi-Fi đã ghi nhớ — trong đó {weakNames.Count} dùng cấu hình yếu (Open/WEP/WPA-PSK)"
                    : $"Có {wifi.Count} Wi-Fi đã ghi nhớ — vi phạm chính sách 'chỉ dùng mạng có dây nội bộ'";
                findings.Add(Finding.Create(
                    id: "NET-WIFI",
                    title: headline,
                    severity: sev,
                    category: "Lịch sử mạng",
                    asset: asset,
                    evidence: string.Join("\n", lines),
                    remediation:
                        "Xóa toàn bộ Wi-Fi profile: 'netsh wlan delete profile name=* i=*' (hoặc Settings → Network & "
                        + "Internet → Wi-Fi → Manage known networks → Forget từng cái). "
                        + (weakNames.Count > 0
                            ? "Ưu tiên xóa ngay các profile [YẾU] vì có thể bị tấn công thụ động lấy mã. "
                            : "")
                        + "Cân nhắc tắt service Wlansvc nếu máy trạm cố định không cần Wi-Fi: 'sc config Wlansvc start=disabled'.",
                    references: RefNetworkList));
            }

            // 4) Current IP plan vs. policy ---------------------------------------------
            // Policy at Công an tỉnh Sơn La: every workstation MUST use a static IP issued
            // by the network admin. Any adapter currently pulling an IP from DHCP is a
            // violation. Static adapters that were recently modified (LastWriteTime within
            // the audit window) are also flagged because changing one static IP to another
            // is required to go through change management.
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đối chiếu cấu hình IP với chính sách (IP tĩnh)", 80));
            ifaces = _ip.Collect();
            var now = DateTime.UtcNow;

            // Two consolidated rows: VIOLATIONS (DHCP + recently-changed static) and
            // COMPLIANT (long-standing static). Severity differs so two rows are right.
            var violations = new List<string>();
            var compliantLines = new List<string>();
            foreach (var i in ifaces)
            {
                var name = i.FriendlyName ?? "(không tên)";
                var changedAt = i.ConfigChangedUtc is null
                    ? "?"
                    : $"{FormatDate(i.ConfigChangedUtc.Value)} UTC";

                if (!i.IsStatic)
                {
                    var lease = i.DhcpLeaseObtainedUtc is null
                        ? "(chưa có lease)"
                        : $"{FormatDate(i.DhcpLeaseObtainedUtc.Value)} UTC";
                    violations.Add(
                        $"• [DHCP] {name} (Guid={i.AdapterGuid})\n"
                        + $"    DhcpIPv4={i.DhcpIpAddress ?? "?"}; DhcpServer={i.DhcpServer ?? "?"}; lease={lease}; cấu hình thay đổi: {changedAt}");
                }
                else
                {
                    var changedRecently = i.ConfigChangedUtc.HasValue
                        && (now - i.ConfigChangedUtc.Value).TotalDays <= StaticIpChangeWindowDays;
                    if (changedRecently)
                    {
                        var ageDays = (int)(now - i.ConfigChangedUtc!.Value).TotalDays;
                        violations.Add(
                            $"• [STATIC mới đổi {ageDays} ngày trước] {name} (Guid={i.AdapterGuid})\n"
                            + $"    StaticIPv4={i.StaticIpv4}; Gateway={i.StaticGatewayIpv4 ?? "?"}; thay đổi: {changedAt}");
                    }
                    else
                    {
                        compliantLines.Add(
                            $"• {name} — StaticIPv4={i.StaticIpv4}; Gateway={i.StaticGatewayIpv4 ?? "?"}; cấu hình thay đổi: {changedAt}");
                    }
                }
            }

            if (violations.Count > 0)
            {
                findings.Add(Finding.Create(
                    id: "NET-IP-VIOLATIONS",
                    title: $"Có {violations.Count}/{ifaces.Count} adapter vi phạm chính sách IP tĩnh (DHCP hoặc mới thay đổi)",
                    severity: Severity.High,
                    category: "Cấu hình mạng",
                    asset: asset,
                    evidence: string.Join("\n", violations),
                    remediation:
                        "DHCP → đặt lại IP tĩnh theo phiếu cấp: Settings → Network & Internet → adapter → 'Edit' IP assignment → 'Manual'. "
                        + "Hoặc PowerShell: New-NetIPAddress -InterfaceAlias \"<tên>\" -IPAddress <ip> -PrefixLength 24 -DefaultGateway <gw>; "
                        + "Set-DnsClientServerAddress -InterfaceAlias \"<tên>\" -ServerAddresses <dns1>,<dns2>. "
                        + "Verify: 'ipconfig /all' phải hiện 'DHCP Enabled = No'. "
                        + "STATIC mới đổi → đối chiếu thời điểm với phiếu thay đổi (change management); nếu không có yêu cầu hợp lệ, "
                        + "khôi phục IP cũ và điều tra (Event Viewer → Security/4719 hoặc Module 6 Log Forensics).",
                    references: RefStaticIp));
            }

            // ALWAYS one compliant/summary row so the section never disappears.
            var dhcpCount = ifaces.Count(x => !x.IsStatic);
            var staticCount = ifaces.Count(x => x.IsStatic);
            findings.Add(Finding.Create(
                id: "NET-IP-SUMMARY",
                title: $"Adapter mạng: {ifaces.Count} (tĩnh: {staticCount}; DHCP: {dhcpCount}; vi phạm: {violations.Count})",
                severity: Severity.Info,
                category: "Cấu hình mạng",
                asset: asset,
                evidence: ifaces.Count == 0
                    ? "Không có adapter mạng IPv4 nào đọc được từ registry."
                    : (compliantLines.Count > 0
                        ? "Adapter phù hợp chính sách:\n" + string.Join("\n", compliantLines)
                        : "Không có adapter nào phù hợp chính sách hiện tại — xem NET-IP-VIOLATIONS."),
                remediation: violations.Count > 0
                    ? "Có vi phạm — xem NET-IP-VIOLATIONS để xử lý từng adapter."
                    : "Tất cả adapter đang dùng IP tĩnh ổn định — phù hợp chính sách."));

            // 5) Outbound Internet egress -----------------------------------------------
            // Workstations operate inside the corporate intranet only; any TCP
            // connection currently established to a public IP is a finding. Group by
            // process so the SOC sees one finding per offending binary even if it has
            // 50 concurrent sockets (browser, sync clients, etc.).
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang phát hiện kết nối ra Internet", 90));
            var egressAll = _egress.Collect();
            var publicEgress = egressAll.Where(e => e.RemoteIsPublic).ToList();
            var byProcess = publicEgress
                .GroupBy(e => (e.ProcessId, e.ProcessName, e.ProcessPath))
                .OrderByDescending(g => g.Count())
                .ToList();

            if (byProcess.Count == 0)
            {
                findings.Add(Finding.Create(
                    id: "NET-EGRESS",
                    title: $"Không có tiến trình nào đang kết nối ra Internet (tổng {egressAll.Count} kết nối TCP nội bộ)",
                    severity: Severity.Info,
                    category: "Kết nối ra Internet",
                    asset: asset,
                    evidence: "Snapshot GetExtendedTcpTable: 0 kết nối ESTABLISHED có IP đích public — phù hợp chính sách.",
                    remediation: "Không cần xử lý.",
                    references: RefEgress));
            }
            else
            {
                // ONE row aggregating EVERY process with public egress. Bullet list ordered
                // by connection count desc.
                var lines = new List<string>(byProcess.Count);
                foreach (var grp in byProcess)
                {
                    var sample = grp.Take(3)
                        .Select(c => $"{c.LocalEndpoint} → {c.RemoteEndpoint}");
                    var moreSuffix = grp.Count() > 3 ? $" (+{grp.Count() - 3})" : "";
                    var path = grp.Key.ProcessPath ?? "(không xác định)";
                    lines.Add(
                        $"• {grp.Key.ProcessName} (PID {grp.Key.ProcessId}) — {grp.Count()} kết nối\n"
                        + $"    Path: {path}\n"
                        + $"    Mẫu: {string.Join(" | ", sample)}{moreSuffix}");
                }
                findings.Add(Finding.Create(
                    id: "NET-EGRESS",
                    title: $"Có {byProcess.Count} tiến trình đang kết nối ra Internet ({publicEgress.Count} kết nối) — vi phạm chính sách mạng nội bộ",
                    severity: Severity.High,
                    category: "Kết nối ra Internet",
                    asset: asset,
                    evidence: string.Join("\n", lines),
                    remediation:
                        "Với mỗi tiến trình trong danh sách: xác minh lý do phải ra Internet trên máy trạm nội bộ. "
                        + "Nếu không có lý do hợp lệ — Stop-Process -Id <pid> -Force, gỡ phần mềm, và chặn ở firewall "
                        + "gateway/UTM theo địa chỉ IP đích. Nếu là phần mềm hợp lệ (AV cập nhật, agent quản lý) — bổ sung "
                        + "vào danh mục trắng và ghi nhận trong nhật ký vận hành.",
                    references: RefEgress));
            }

            // 6) Internet egress HISTORY from SRUM ---------------------------------------
            // Reaches back ~30 days for per-app bytes-sent + bytes-received aggregate.
            // Complements the live-snapshot NET-EGRESS above with longitudinal data — answers
            // "did this app reach the network last week even though it's idle right now?".
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang đọc lịch sử egress từ SRUM (30 ngày)", 95));
            SrumEgressHistoryResult srumResult;
            try
            {
                srumResult = _srum.Collect(daysBack: 30);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SRUM history collector threw");
                srumResult = SrumEgressHistoryResult.Failed(
                    $"Lỗi không xác định khi đọc SRUM: {ex.GetType().Name} {ex.Message}");
            }
            EmitSrumFinding(findings, asset, srumResult);

            // Snapshot publish ----------------------------------------------------------
            context.SetShared(SharedSnapshotKey, new DeviceForensicsSnapshot(
                UsbCount: usbs.Count,
                PortablePhoneCount: phoneCount,
                PortableOtherCount: otherCount,
                NetworkProfileCount: nets.Count,
                NetworkProfileWiFiCount: nets.Count(n => n.NameType == 6),
                NetworkProfileMobileCount: nets.Count(n => n.NameType == 71),
                WifiRememberedCount: wifi.Count,
                InterfaceCount: ifaces.Count,
                InterfaceStaticCount: ifaces.Count(i => i.IsStatic),
                InternetEgressConnectionCount: publicEgress.Count,
                InternetEgressDistinctProcesses: byProcess.Count));

            progress.Report(new ProgressUpdate(Metadata.Id, "Hoàn tất", 100));
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DeviceForensicsModule failed");
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = ex.Message,
                Findings = findings
            });
        }
    }

    /// <summary>
    /// Emit SRUM history findings split by interface attribution. SRUM rows carry the
    /// interface LUID so we know whether the bytes left through an Internet-facing NIC
    /// (gateway present) or a LAN-only one (no gateway — VMware vmnet, internal-only
    /// adapters). Two findings are emitted:
    /// <list type="bullet">
    ///   <item><c>NET-EGRESS-HIST-INTERNET</c> — High when ≥1 app moved bytes through
    ///         an Internet-facing interface; lists those apps with bytes-sent + recv.</item>
    ///   <item><c>NET-EGRESS-HIST-LAN</c> — Info, lists apps whose ONLY traffic was on
    ///         LAN-only interfaces (no policy concern, kept for completeness).</item>
    /// </list>
    /// On collector failure a single Info row carries the diagnostic.
    /// </summary>
    private static void EmitSrumFinding(List<object> findings, string asset, SrumEgressHistoryResult r)
    {
        if (!r.Succeeded)
        {
            findings.Add(Finding.Create(
                id: "NET-EGRESS-HIST",
                title: "Lịch sử egress 30 ngày (SRUM): không đọc được",
                severity: Severity.Info,
                category: "Kết nối ra Internet",
                asset: asset,
                evidence: r.Status,
                remediation:
                    "SRUM nằm tại C:\\Windows\\System32\\sru\\SRUDB.dat (ESE database, được bật mặc định trên Win10/11). "
                    + "Yêu cầu: chạy SecAudit dưới quyền Administrator + Volume Shadow Copy service (VSS) đang bật. "
                    + "Có thể test thủ công bằng: 'esentutl /y /vss C:\\Windows\\System32\\sru\\SRUDB.dat /d C:\\Temp\\SRUDB.dat'.",
                references: RefEgress));
            return;
        }

        const int TopN = 20;

        // Split: apps with Internet bytes vs LAN-only.
        var internetApps = r.PerApp
            .Where(a => a.HasInternetTraffic)
            .OrderByDescending(a => a.TotalInternetBytes)
            .ToList();
        var lanOnlyApps = r.PerApp
            .Where(a => !a.HasInternetTraffic && a.TotalLanBytes > 0)
            .OrderByDescending(a => a.TotalLanBytes)
            .ToList();

        // ----- 1) Internet egress history (HIGH if any app, Info if none) -----
        if (internetApps.Count == 0)
        {
            findings.Add(Finding.Create(
                id: "NET-EGRESS-HIST-INTERNET",
                title: $"Lịch sử egress {r.DaysCovered} ngày (SRUM): KHÔNG có app nào ra Internet",
                severity: Severity.Info,
                category: "Kết nối ra Internet",
                asset: asset,
                evidence: "Không có sự kiện SRUM nào ghi nhận lưu lượng qua interface có default gateway "
                          + "(Internet-facing). Phù hợp chính sách mạng nội bộ.",
                remediation: "Không cần xử lý.",
                references: RefEgress));
        }
        else
        {
            var top = internetApps.Take(TopN).ToList();
            var lines = top.Select(app =>
            {
                var sentMb = app.BytesSentInternet / 1024.0 / 1024.0;
                var recvMb = app.BytesReceivedInternet / 1024.0 / 1024.0;
                var totalMb = sentMb + recvMb;
                var first = app.FirstSeenUtc.HasValue ? FormatDate(app.FirstSeenUtc.Value) : "?";
                var last = app.LastSeenUtc.HasValue ? FormatDate(app.LastSeenUtc.Value) : "?";
                return $"• {app.AppLabel}\n"
                       + $"    Internet: tổng {totalMb:F1} MB (gửi {sentMb:F1}, nhận {recvMb:F1}); "
                       + $"từ {first} → {last} UTC";
            }).ToList();
            var more = internetApps.Count - top.Count;
            if (more > 0) { lines.Add($"• ... (+{more} app khác — xem JSON)"); }

            findings.Add(Finding.Create(
                id: "NET-EGRESS-HIST-INTERNET",
                title: $"Lịch sử egress {r.DaysCovered} ngày (SRUM): {internetApps.Count} app đã ra Internet — vi phạm chính sách",
                severity: Severity.High,
                category: "Kết nối ra Internet",
                asset: asset,
                evidence: string.Join("\n", lines),
                remediation:
                    "Đối chiếu từng app trong danh sách với danh mục phần mềm được cấp phép. "
                    + "App lạ hoặc app không có nhu cầu ra Internet (VD: phần mềm nghiệp vụ nội bộ) "
                    + "có hàng MB→GB qua Internet là dấu hiệu cần điều tra. Cross-reference với "
                    + "NET-EGRESS (live snapshot) để biết app nào CÒN đang kết nối ngay lúc quét.",
                references: RefEgress));
        }

        // ----- 2) LAN-only history (Info, không cảnh báo) -----
        if (lanOnlyApps.Count > 0)
        {
            var top = lanOnlyApps.Take(TopN).ToList();
            var lines = top.Select(app =>
            {
                var sentMb = app.BytesSentLan / 1024.0 / 1024.0;
                var recvMb = app.BytesReceivedLan / 1024.0 / 1024.0;
                var totalMb = sentMb + recvMb;
                return $"• {app.AppLabel} — tổng {totalMb:F1} MB (gửi {sentMb:F1}, nhận {recvMb:F1}) qua interface LAN-only";
            }).ToList();
            var more = lanOnlyApps.Count - top.Count;
            if (more > 0) { lines.Add($"• ... (+{more} app khác — xem JSON)"); }

            findings.Add(Finding.Create(
                id: "NET-EGRESS-HIST-LAN",
                title: $"Lịch sử egress {r.DaysCovered} ngày (SRUM): {lanOnlyApps.Count} app chỉ chạy trên mạng nội bộ",
                severity: Severity.Info,
                category: "Kết nối ra Internet",
                asset: asset,
                evidence: string.Join("\n", lines),
                remediation: "Không cần xử lý — đây là lưu lượng nội bộ, đúng chính sách. "
                             + "Liệt kê để admin có cái nhìn đầy đủ về app nào đã sử dụng mạng.",
                references: RefEgress));
        }
    }

    /// <summary>
    /// Classify a NetworkList profile as worth surfacing or not, given the policy
    /// "máy chỉ được kết nối nội bộ".
    /// </summary>
    private static (Severity? Sev, string Why) ClassifyNetwork(NetworkProfileRecord n)
    {
        // Domain-authenticated wired profile = the corporate LAN ⇒ expected, no finding.
        if (n.Category == 2 && n.NameType is 23 or null)
        {
            return (null, "");
        }
        return n.NameType switch
        {
            6 => (Severity.High, "kết nối Wi-Fi đã được ghi nhớ — chính sách chỉ cho phép mạng nội bộ có dây."),
            71 => (Severity.High, "kết nối mobile broadband (3G/4G/5G) — kênh ngoài đường truyền nội bộ."),
            81 => (Severity.High, "VPN profile đã được tạo — kiểm tra xem có nằm trong danh mục VPN được cấp phép không."),
            _ when n.Category == 0 => (Severity.Medium, "mạng được đánh dấu Public — bất thường trên máy chỉ chạy trong nội bộ."),
            _ => (Severity.Info, "mạng đã từng kết nối")
        };
    }

    private static bool IsWeakWifi(WifiProfileRecord w)
    {
        var auth = w.AuthMethod.ToUpperInvariant();
        return auth is "OPEN" or "SHARED" or "WEP" or "WPA" or "WPA-PSK";
    }

    /// <summary>
    /// Emit one consolidated finding for Wi-Fi adapters that left Wlansvc interface
    /// folders behind. The collector can return several stale interface GUIDs for the
    /// same physical adapter after driver updates, so group by PnP instance ID when
    /// available and keep orphan GUIDs as individual evidence rows.
    /// </summary>
    private static void EmitWifiAdapterFinding(
        List<object> findings,
        string asset,
        IReadOnlyList<WifiAdapterRecord> adapters)
    {
        if (adapters.Count == 0)
        {
            return;
        }

        var grouped = adapters
            .GroupBy(
                a => string.IsNullOrWhiteSpace(a.PnpInstanceId)
                    ? a.InterfaceGuid
                    : a.PnpInstanceId,
                StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var rows = g.ToList();
                var representative = rows
                    .OrderByDescending(a => a.IsCurrentlyAttached)
                    .ThenByDescending(a => a.ProfilesStoredCount)
                    .ThenByDescending(a => a.LastSeenUtc ?? DateTime.MinValue)
                    .First();
                return new
                {
                    Rows = rows,
                    Adapter = representative,
                    Profiles = rows.Sum(a => a.ProfilesStoredCount),
                    LastSeen = rows
                        .Select(a => a.LastSeenUtc)
                        .Where(d => d.HasValue)
                        .Select(d => d!.Value)
                        .DefaultIfEmpty(DateTime.MinValue)
                        .Max(),
                    Attached = rows.Any(a => a.IsCurrentlyAttached)
                };
            })
            .OrderByDescending(g => g.Adapter.BusType == "USB")
            .ThenByDescending(g => g.Adapter.BusType is "PCI" or "SDIO")
            .ThenByDescending(g => g.Attached)
            .ThenByDescending(g => g.Profiles)
            .ToList();

        int physicalCount = grouped.Count(g => g.Adapter.BusType is "PCI" or "USB" or "SDIO");
        int usbCount = grouped.Count(g => g.Adapter.BusType == "USB");
        int attachedCount = grouped.Count(g => g.Attached);
        var severity = usbCount > 0
            ? Severity.High
            : physicalCount > 0
                ? Severity.Medium
                : Severity.Info;

        var lines = grouped.Select(g =>
        {
            var a = g.Adapter;
            var name = a.FriendlyName ?? a.Description ?? "(unknown adapter)";
            var pnp = string.IsNullOrWhiteSpace(a.PnpInstanceId) ? "(no PnP id)" : a.PnpInstanceId;
            var lastSeen = g.LastSeen == DateTime.MinValue ? "?" : FormatDate(g.LastSeen) + " UTC";
            var state = g.Attached ? "currently attached" : "not currently attached";
            var staleGuids = g.Rows.Count - 1;
            var staleText = staleGuids > 0 ? $"; stale interface GUIDs={staleGuids}" : "";
            return $"- [{a.BusType}] {name} ({state})\n"
                   + $"    PnP={pnp}; profiles stored={g.Profiles}; last seen={lastSeen}{staleText}\n"
                   + $"    Interface GUID(s): {string.Join(", ", g.Rows.Select(x => x.InterfaceGuid))}";
        });

        findings.Add(Finding.Create(
            id: "NET-WIFI-ADAPTER",
            title: $"Lịch sử Wi-Fi adapter: {grouped.Count} adapter logic, vật lý={physicalCount}, USB={usbCount}, đang gắn={attachedCount}",
            severity: severity,
            category: "Lịch sử mạng",
            asset: asset,
            evidence: string.Join("\n", lines),
            remediation:
                "Đối chiếu từng Wi-Fi adapter với danh mục thiết bị được phép. USB Wi-Fi dongle hoặc adapter không còn gắn "
                + "nhưng vẫn có Wlansvc profile folder là dấu vết cần xác minh với người dùng. Nếu máy trạm chỉ được dùng LAN có dây, "
                + "gỡ driver/vô hiệu hóa adapter Wi-Fi không được phép và bật GPO chặn cài đặt thiết bị wireless lạ.",
            references: RefNetworkList));
    }

    private static string CategoryLabel(int c) => c switch
    {
        0 => "Public",
        1 => "Private",
        2 => "DomainAuthenticated",
        _ => $"?({c})"
    };

    private static string NameTypeLabel(int? t) => t switch
    {
        null => "?",
        6 => "Wi-Fi",
        23 => "Có dây",
        71 => "Mobile broadband",
        81 => "VPN",
        _ => $"loại {t}"
    };

    private static string IfSummary(InterfaceIpRecord i)
    {
        var name = i.FriendlyName ?? i.AdapterGuid;
        return i.IsStatic
            ? $"{name}=Static {i.StaticIpv4}"
            : $"{name}=DHCP {i.DhcpIpAddress ?? "(no lease)"}";
    }

    private static string FormatDate(DateTime t) =>
        t.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    /// <summary>
    /// Render the FirstInstall / LastArrival / LastRemoval triple plus the install-event
    /// counter into a single human-readable evidence fragment. Each missing field is
    /// rendered as "không rõ" so the SOC operator can see whether the data point is
    /// genuinely absent vs. simply stale.
    /// </summary>
    private static string BuildLifecycleString(
        DateTime? firstInstall, DateTime? lastArrival, DateTime? lastRemoval, int installCount)
    {
        var parts = new List<string>(4);
        parts.Add(firstInstall is null
            ? "lần cài đầu: không rõ"
            : $"lần cài đầu: {FormatDate(firstInstall.Value)} UTC");
        parts.Add(lastArrival is null
            ? "lần cắm gần nhất: không rõ"
            : $"lần cắm gần nhất: {FormatDate(lastArrival.Value)} UTC");
        parts.Add(lastRemoval is null
            ? "lần tháo gần nhất: không rõ"
            : $"lần tháo gần nhất: {FormatDate(lastRemoval.Value)} UTC");
        parts.Add($"số lần cài driver (setupapi): {installCount}");
        return string.Join("; ", parts);
    }

    private static string Sanitize(string s)
    {
        var chars = s.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_').ToArray();
        var result = new string(chars);
        return result.Length > 40 ? result[..40] : result;
    }
}
