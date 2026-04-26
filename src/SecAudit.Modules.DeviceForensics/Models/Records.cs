namespace SecAudit.Modules.DeviceForensics.Models;

/// <summary>
/// One USB mass-storage device that has ever been mounted on this machine. Sourced from
/// <c>HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR</c>.
///
/// <para>
/// Timestamps come from two complementary sources:
/// <list type="bullet">
///   <item><see cref="FirstInstallUtc"/> / <see cref="LastArrivalUtc"/> /
///         <see cref="LastRemovalUtc"/> — Windows 10+ DEVPKEY values stored under
///         <c>...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\{0065|0066|0067}</c>.
///         These are the authoritative per-device "last connected at" timestamps.</item>
///   <item><see cref="InstallEventCount"/> — number of <c>Device Install</c> events for this
///         device in <c>C:\Windows\inf\setupapi.dev.log</c>. This counts driver
///         installs/reinstalls, NOT individual plug-in events. A USB stick that has been
///         plugged 50 times typically shows InstallEventCount=1 (driver was set up once).</item>
/// </list>
/// </para>
/// </summary>
public sealed record UsbStorageRecord(
    string Vendor,
    string Product,
    string Revision,
    string SerialNumber,
    string? FriendlyName,
    DateTime? FirstInstallUtc,
    DateTime? LastArrivalUtc,
    DateTime? LastRemovalUtc,
    int InstallEventCount,
    string DeviceInstanceId);

/// <summary>
/// One Windows Portable Device (MTP/PTP) that has ever been mounted — typically an
/// Android/iOS phone or a digital camera. Sourced from
/// <c>HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices</c>, joined with the matching
/// <c>HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&amp;PID_yyyy\&lt;serial&gt;</c> device key
/// for DEVPKEY arrival/removal timestamps.
/// </summary>
public sealed record PortableDeviceRecord(
    string DeviceInstanceId,
    string FriendlyName,
    bool LooksLikePhone,
    DateTime? FirstInstallUtc,
    DateTime? LastArrivalUtc,
    DateTime? LastRemovalUtc,
    int InstallEventCount);

/// <summary>
/// One network profile the machine has ever joined. Combines two registry sources:
/// <list type="bullet">
///   <item><c>NetworkList\Profiles\{guid}</c> — friendly name, category, dates</item>
///   <item><c>NetworkList\Signatures\{Managed|Unmanaged}\{sig}</c> — DefaultGatewayMac, Description (often the SSID)</item>
/// </list>
///
/// <para>
/// <c>Category</c> is the Windows network-location classifier: 0 = Public, 1 = Private,
/// 2 = DomainAuthenticated. <c>Source</c> is the parent collection: "Managed" (domain
/// network discovered via group policy) or "Unmanaged" (everything else, including WiFi,
/// home Ethernet, mobile broadband, VPN). <c>NameType</c> from the Profile key:
/// 6 = wireless, 23 = wired, 71 = mobile broadband, 81 = VPN, others = misc.
/// </para>
/// </summary>
public sealed record NetworkProfileRecord(
    string ProfileGuid,
    string ProfileName,
    int Category,
    string Source,
    string? Description,
    string? DefaultGatewayMac,
    int? NameType,
    DateTime? FirstConnectedUtc,
    DateTime? LastConnectedUtc);

/// <summary>
/// One Wi-Fi profile the machine has memorised. Sourced from
/// <c>%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\{guid}\{profile}.xml</c>.
/// </summary>
public sealed record WifiProfileRecord(
    string ProfileName,
    string AuthMethod,
    string EncryptionMethod,
    string ConnectionMode);

/// <summary>
/// Snapshot of one network adapter's IP configuration as currently committed to the
/// registry. <see cref="IsStatic"/> reflects the registry intent (EnableDHCP=0 +
/// non-empty IPAddress), independent of whatever DHCP may have leased at runtime.
///
/// <para>
/// <see cref="ConfigChangedUtc"/> is the LastWriteTime of the
/// <c>Tcpip\Parameters\Interfaces\{guid}</c> registry key — i.e. the last moment ANY
/// IP-related value (EnableDHCP, IPAddress, DefaultGateway, SubnetMask, NameServer) was
/// written. Useful as the "lần cuối thay đổi cấu hình IP" timestamp for compliance audits.
/// On a DHCP adapter this also bumps on every lease renewal, so it is most meaningful for
/// adapters where <see cref="IsStatic"/> is true.
/// </para>
/// </summary>
public sealed record InterfaceIpRecord(
    string AdapterGuid,
    string? FriendlyName,
    bool IsStatic,
    string? StaticIpv4,
    string? StaticGatewayIpv4,
    string? DhcpIpAddress,
    string? DhcpServer,
    DateTime? DhcpLeaseObtainedUtc,
    DateTime? ConfigChangedUtc);

/// <summary>
/// One outbound TCP connection observed by <c>GetExtendedTcpTable</c> at audit time.
/// Used to surface Internet egress on a workstation that should be operating only inside
/// the corporate intranet.
///
/// <para>
/// <see cref="RemoteIsPublic"/> is <c>true</c> when the remote endpoint is NOT in any of:
/// RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16),
/// CGNAT (100.64/10), broadcast (255.255.255.255), or 0.0.0.0 — i.e. the connection is
/// actually leaving the LAN.
/// </para>
/// </summary>
public sealed record EgressConnectionRecord(
    int ProcessId,
    string ProcessName,
    string? ProcessPath,
    string LocalEndpoint,
    string RemoteEndpoint,
    string RemoteAddress,
    int RemotePort,
    bool RemoteIsPublic,
    string Protocol);

/// <summary>
/// One observation of a removable storage device being mounted on this machine, parsed
/// from a Windows event-log entry (Microsoft-Windows-Partition/Diagnostic 1006). Multiple
/// events may share the same <see cref="SerialNumber"/> — that <i>is</i> the connection
/// history for that device.
///
/// <para>
/// <see cref="Source"/> records which event-log channel + ID produced this datapoint so
/// the SOC operator can pivot back to Event Viewer for full XML when needed.
/// </para>
/// </summary>
public sealed record DeviceConnectionEvent(
    DateTime AtUtc,
    string Manufacturer,
    string Model,
    string Revision,
    string SerialNumber,
    long? CapacityBytes,
    string Source);

/// <summary>
/// Per-application network-egress aggregate from the SRUM database, summed over the
/// caller's lookback window. Bytes are split into <i>Internet-facing interface</i> vs
/// <i>LAN-only interface</i> totals — an interface counts as Internet-facing when its
/// IPv4 properties carry at least one non-zero default gateway. This isn't perfect (a
/// VPN tunnel will look Internet-facing too) but is the most accurate split achievable
/// purely from SRUM data without DNS resolution.
/// </summary>
public sealed record SrumEgressPerApp(
    string AppLabel,
    ulong BytesSentInternet,
    ulong BytesReceivedInternet,
    ulong BytesSentLan,
    ulong BytesReceivedLan,
    DateTime? FirstSeenUtc,
    DateTime? LastSeenUtc)
{
    public ulong TotalInternetBytes => BytesSentInternet + BytesReceivedInternet;
    public ulong TotalLanBytes => BytesSentLan + BytesReceivedLan;
    public bool HasInternetTraffic => TotalInternetBytes > 0;
}

/// <summary>
/// Outcome of a SRUM history extraction. <see cref="Status"/> carries a human-readable
/// reason when extraction failed so the caller can surface it as evidence rather than
/// silently swallowing the absence of data.
/// </summary>
public sealed record SrumEgressHistoryResult(
    bool Succeeded,
    string Status,
    IReadOnlyList<SrumEgressPerApp> PerApp,
    int DaysCovered)
{
    public static SrumEgressHistoryResult Failed(string reason) =>
        new(false, reason, Array.Empty<SrumEgressPerApp>(), 0);

    public static SrumEgressHistoryResult Ok(IReadOnlyList<SrumEgressPerApp> perApp, int daysCovered) =>
        new(true, "OK", perApp, daysCovered);
}

/// <summary>
/// Cross-module snapshot for the report's "Phạm vi quét" section. Lets the formal report
/// show denominators ("8 USB / 2 điện thoại / 1 WiFi đã ghi nhớ") instead of just emitted
/// finding counts.
/// </summary>
public sealed record DeviceForensicsSnapshot(
    int UsbCount,
    int PortablePhoneCount,
    int PortableOtherCount,
    int NetworkProfileCount,
    int NetworkProfileWiFiCount,
    int NetworkProfileMobileCount,
    int WifiRememberedCount,
    int InterfaceCount,
    int InterfaceStaticCount,
    int InternetEgressConnectionCount = 0,
    int InternetEgressDistinctProcesses = 0);
