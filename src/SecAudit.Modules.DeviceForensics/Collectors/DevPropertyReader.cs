using System.Runtime.Versioning;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Reads Windows Plug-and-Play DEVPKEY values stored under a device's Enum subkey.
///
/// <para>
/// Registry shape (Win10+ — verified by inspection of <c>USBSTOR\...\Properties\</c>):
/// <code>
/// &lt;deviceKey&gt;\Properties\{fmtId-as-braced-guid}\&lt;propId-4hex&gt;\&lt;index-8hex&gt;
///   (Default) : REG_BINARY = property data (FILETIME = 8 bytes for date properties)
/// </code>
/// On older builds the index level is omitted; we fall back to that shape too.
/// </para>
///
/// <para>
/// Format ID for the device-lifecycle properties is
/// <c>{83da6326-97a6-4088-9453-a1923f573b29}</c>. Property IDs of interest:
/// <list type="bullet">
///   <item><c>0x65</c> (101) = DEVPKEY_Device_FirstInstallDate</item>
///   <item><c>0x66</c> (102) = DEVPKEY_Device_LastArrivalDate ← "lần cuối kết nối"</item>
///   <item><c>0x67</c> (103) = DEVPKEY_Device_LastRemovalDate ← "lần cuối tháo"</item>
/// </list>
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DevPropertyReader
{
    public const string LifecycleFormatGuid = "{83da6326-97a6-4088-9453-a1923f573b29}";
    public const string FirstInstallPropId = "0065";
    public const string LastArrivalPropId = "0066";
    public const string LastRemovalPropId = "0067";

    private readonly IRegistryReader _registry;

    public DevPropertyReader(IRegistryReader registry)
    {
        _registry = registry;
    }

    /// <summary>
    /// Read a DEVPKEY date property (FILETIME, 8 bytes little-endian) and convert to UTC
    /// DateTime. Returns null if the property is missing, malformed, or — crucially —
    /// access-denied.
    ///
    /// <para>
    /// On Win10/11, the <c>Properties</c> subkey under each device's enum entry is
    /// frequently ACLed for SYSTEM-only or TrustedInstaller-only read; even an elevated
    /// Administrator process gets <c>SecurityException</c> /
    /// <c>UnauthorizedAccessException</c> on <c>RegOpenKeyEx</c>. Callers iterate hundreds
    /// of devices, so a single denied key MUST NOT abort the loop. Therefore this method
    /// swallows every registry-related exception and returns null — the higher-level
    /// finding renderer will display "không rõ" for that timestamp, which is the correct
    /// signal to the operator (data exists but is gated by ACL, not absent).
    /// </para>
    /// </summary>
    public DateTime? ReadFiletime(string deviceKeyPath, string fmtIdGuid, string propId4Hex)
    {
        try
        {
            var basePath = $@"{deviceKeyPath}\Properties\{fmtIdGuid}\{propId4Hex}";

            // Layered lookup — try the indexed shape first (Win10+), fall back to two
            // pre-Win10 alternatives. Cheap because GetValue returns null fast on missing.
            var raw = SafeGet($@"{basePath}\00000000", "")
                   ?? SafeGet(basePath, "")
                   ?? SafeGet($@"{deviceKeyPath}\Properties\{fmtIdGuid}", propId4Hex);

            if (raw is byte[] bytes && bytes.Length >= 8)
            {
                try
                {
                    var ft = BitConverter.ToInt64(bytes, 0);
                    if (ft <= 0) { return null; }
                    return DateTime.FromFileTimeUtc(ft);
                }
                catch (ArgumentOutOfRangeException)
                {
                    return null;
                }
            }
            return null;
        }
        catch
        {
            // Belt-and-suspenders: SafeGet already swallows; this guards against any
            // exotic exception (e.g. IOException on a corrupt offline hive) — same
            // semantics as a missing property.
            return null;
        }
    }

    /// <summary>
    /// Wrap a single registry GetValue call so denied/missing keys map to <c>null</c>
    /// rather than throwing — letting the layered fallback in
    /// <see cref="ReadFiletime"/> try the next shape.
    /// </summary>
    private object? SafeGet(string keyPath, string valueName)
    {
        try
        {
            return _registry.GetValue(RegistryHive.LocalMachine, keyPath, valueName);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Convenience: read first-install / last-arrival / last-removal in one call.
    /// </summary>
    public (DateTime? FirstInstall, DateTime? LastArrival, DateTime? LastRemoval)
        ReadDeviceLifecycle(string deviceKeyPath)
        => (
            ReadFiletime(deviceKeyPath, LifecycleFormatGuid, FirstInstallPropId),
            ReadFiletime(deviceKeyPath, LifecycleFormatGuid, LastArrivalPropId),
            ReadFiletime(deviceKeyPath, LifecycleFormatGuid, LastRemovalPropId));
}
