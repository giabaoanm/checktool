using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;
using SecAudit.Modules.DeviceForensics.Models;

namespace SecAudit.Modules.DeviceForensics.Collectors;

/// <summary>
/// Enumerates every Windows Portable Device (MTP/PTP) ever attached. The persistent
/// store is <c>HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices</c> — survives
/// reboots and uninstalls, so it doubles as a "phone-attached-this-machine" timeline
/// for IR.
///
/// <para>
/// Lifecycle timestamps come from the underlying USB enumerator key
/// <c>HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&amp;PID_yyyy\&lt;serial&gt;</c> via
/// <see cref="DevPropertyReader"/>. The WPD instance id (URL-encoded) is decoded and the
/// embedded <c>USB#VID_xxxx#PID_yyyy#&lt;serial&gt;</c> segment is mapped to the matching
/// Enum subtree.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PortableDeviceCollector
{
    private const string DevicesKey = @"SOFTWARE\Microsoft\Windows Portable Devices\Devices";
    private const string UsbEnumRoot = @"SYSTEM\CurrentControlSet\Enum\USB";
    private static readonly string[] PortablePrefixes = { "USB\\", "SWD\\WPDBUSENUM\\" };

    /// <summary>
    /// Substrings — lower-cased, OrdinalIgnoreCase — that strongly indicate a phone or
    /// tablet rather than a camera/printer/MP3-player. Curated for the Vietnam SMB
    /// environment where iPhone, Samsung, OPPO, Vivo, Xiaomi, Realme are dominant.
    /// </summary>
    private static readonly string[] PhoneTokens =
    {
        "iphone", "ipad", "ipod",
        "android", "samsung", "galaxy", "sm-",
        "pixel", "huawei", "honor", "redmi", "xiaomi", "mi ",
        "oppo", "realme", "vivo", "iqoo",
        "oneplus", "nokia", "asus rog phone", "rog phone",
        "lg-", "sony xperia", "xperia",
        "motorola", "moto ",
        "nubia", "infinix", "tecno",
    };

    private readonly IRegistryReader _registry;
    private readonly DevPropertyReader _devProps;
    private readonly UsbStorageHistoryCollector _setupApi; // reuse parser for install counts
    private readonly ILogger<PortableDeviceCollector> _logger;

    public PortableDeviceCollector(
        IRegistryReader registry,
        DevPropertyReader devProps,
        UsbStorageHistoryCollector setupApi,
        ILogger<PortableDeviceCollector> logger)
    {
        _registry = registry;
        _devProps = devProps;
        _setupApi = setupApi;
        _logger = logger;
    }

    public IReadOnlyList<PortableDeviceRecord> Collect()
    {
        var results = new List<PortableDeviceRecord>();
        IReadOnlyList<string> instanceIds;
        try
        {
            instanceIds = _registry.GetSubKeyNames(RegistryHive.LocalMachine, DevicesKey);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cannot enumerate Windows Portable Devices key");
            return results;
        }

        // For install counts, accept both the USB and SWD prefixes — phones surface under
        // both depending on whether they expose MTP, PTP or mass-storage personalities.
        var installCounts = _setupApi.ParseSetupApiInstallCounts(PortablePrefixes);

        foreach (var raw in instanceIds)
        {
            // Skip internal volumes — Windows registers every fixed NTFS volume as a
            // WPD entry too. Those have InstanceIds like
            // SWD#WPDBUSENUM#{class-guid}#XXXXXXXXXXXXXXXX with NO embedded USBSTOR / USB
            // segment and friendly names like "DATA HDPLUS", "HD", "DATA1" or just "H:\".
            // Real removable devices always carry _??_USBSTOR# or _??_USB# in their
            // SWD-rooted instance id (or start with USB#).
            if (IsInternalVolumeWpd(raw))
            {
                continue;
            }

            var friendly = _registry.GetValue(
                RegistryHive.LocalMachine, $@"{DevicesKey}\{raw}", "FriendlyName") as string
                ?? string.Empty;

            // Decode the URL-style instance id and try to locate the matching USB enum key
            // for DEVPKEY lookup.
            var enumKeyPath = TryResolveUsbEnumKey(raw);
            DateTime? firstInstall = null, lastArrival = null, lastRemoval = null;
            if (enumKeyPath is not null)
            {
                try
                {
                    (firstInstall, lastArrival, lastRemoval) = _devProps.ReadDeviceLifecycle(enumKeyPath);
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "DEVPKEY lookup failed for {Device}", enumKeyPath);
                }
                // Fallback: when DEVPKEY is denied, use the underlying USB enum key's
                // LastWriteTime as an approximate "last seen" indicator. Less precise
                // than the PnP-managed timestamps but still actionable.
                if (lastArrival is null)
                {
                    lastArrival = _registry.GetLastWriteTime(RegistryHive.LocalMachine, enumKeyPath);
                }
            }

            // setupapi count is keyed on the original USB instance id — decode raw to
            // produce the same string the log writes.
            var decodedInstance = DecodeInstanceForSetupApi(raw);
            int installCount = 0;
            if (decodedInstance is not null
                && installCounts.TryGetValue(decodedInstance.ToLowerInvariant(), out var c))
            {
                installCount = c;
            }

            results.Add(new PortableDeviceRecord(
                DeviceInstanceId: raw,
                FriendlyName: friendly,
                LooksLikePhone: LooksLikePhone(friendly, raw),
                FirstInstallUtc: firstInstall,
                LastArrivalUtc: lastArrival,
                LastRemovalUtc: lastRemoval,
                InstallEventCount: installCount));
        }

        return results
            .OrderByDescending(r => r.LastArrivalUtc ?? r.FirstInstallUtc ?? DateTime.MinValue)
            .ToList();
    }

    /// <summary>
    /// The WPD store key uses URL-style # separators, e.g.
    /// <c>USB#VID_04E8&amp;PID_6860&amp;MS_COMP_MTP&amp;SAMSUNG_ANDROID#6&amp;2C839313&amp;1&amp;0000#{guid}</c>.
    /// Translate that into the registry path <c>...\Enum\USB\VID_04E8&amp;PID_6860&amp;...\6&amp;2C839313&amp;1&amp;0000</c>.
    /// Returns null if the id does not start with <c>USB#</c>.
    /// </summary>
    private string? TryResolveUsbEnumKey(string wpdInstanceId)
    {
        // Strip a leading "SWD#WPDBUSENUM#" prefix that some MTP devices use — the rest
        // is "_??_USBSTOR#..." or "_??_USB#..." with literal "_??_" escape.
        var trimmed = wpdInstanceId;
        const string swdPrefix = "SWD#WPDBUSENUM#";
        if (trimmed.StartsWith(swdPrefix, StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed.Substring(swdPrefix.Length).TrimStart('_', '?');
        }

        if (!trimmed.StartsWith("USB#", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        // Drop the trailing "#{class-guid}" if present.
        var guidStart = trimmed.LastIndexOf("#{", StringComparison.Ordinal);
        if (guidStart > 0)
        {
            trimmed = trimmed.Substring(0, guidStart);
        }

        // Replace the URL '#' separators with backslashes — that yields the registry path
        // segment. "USB#VID_x#serial" → "USB\VID_x\serial".
        var asPath = trimmed.Replace('#', '\\');
        // Already begins with "USB\..." — anchor under SYSTEM\CurrentControlSet\Enum.
        var full = $@"SYSTEM\CurrentControlSet\Enum\{asPath}";

        // Verify the key actually exists before returning — keeps DEVPKEY lookup quiet
        // when the instance id maps to a USBSTOR device (mass storage personality of
        // the same phone, handled elsewhere) instead of a USB one.
        try
        {
            _ = _registry.GetSubKeyNames(RegistryHive.LocalMachine, full);
            return full;
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Cannot resolve enum key for WPD id {Id}", wpdInstanceId);
            return null;
        }
    }

    /// <summary>
    /// Setupapi.dev.log records device installs by their full Plug-and-Play instance id
    /// using backslashes (e.g. <c>USB\VID_04E8&amp;PID_6860&amp;MS_COMP_MTP&amp;SAMSUNG_ANDROID\6&amp;2C839313&amp;1&amp;0000</c>).
    /// Translate the WPD-style <c>#</c>-separated id into that form.
    /// </summary>
    private static string? DecodeInstanceForSetupApi(string wpdInstanceId)
    {
        var trimmed = wpdInstanceId;
        const string swdPrefix = "SWD#WPDBUSENUM#";
        if (trimmed.StartsWith(swdPrefix, StringComparison.OrdinalIgnoreCase))
        {
            // SWD\WPDBUSENUM\<inner> is exactly what setupapi writes for these.
            return $@"SWD\WPDBUSENUM\{wpdInstanceId.Substring(swdPrefix.Length)}";
        }
        if (!trimmed.StartsWith("USB#", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        var guidStart = trimmed.LastIndexOf("#{", StringComparison.Ordinal);
        if (guidStart > 0)
        {
            trimmed = trimmed.Substring(0, guidStart);
        }
        return trimmed.Replace('#', '\\');
    }

    /// <summary>
    /// Internal NTFS volumes (the user's local hard drives, internal SSD partitions)
    /// are also registered as WPD entries by Windows. Their instance IDs have the
    /// form <c>SWD\WPDBUSENUM\{class-guid}\&lt;hex&gt;</c> — no embedded
    /// <c>USBSTOR</c> / <c>USB</c> segment marker. Real removable WPD devices always
    /// carry one of those markers. This filter drops the internal-volume noise
    /// (operator at Sơn La saw "DATA HDPLUS", "HD", "DATA1", "H:\" listed as if they
    /// were external devices).
    /// </summary>
    internal static bool IsInternalVolumeWpd(string instanceId)
    {
        if (string.IsNullOrEmpty(instanceId)) { return false; }
        // Real removable: SWD#WPDBUSENUM#_??_USBSTOR# OR _??_USB# OR USB# directly.
        var lower = instanceId.ToLowerInvariant();
        if (lower.Contains("usbstor#", StringComparison.Ordinal)) { return false; }
        if (lower.Contains("_??_usb#", StringComparison.Ordinal)) { return false; }
        if (lower.StartsWith("usb#", StringComparison.Ordinal)) { return false; }
        // Anything else under SWD#WPDBUSENUM with a class-guid ID is an internal volume.
        return lower.StartsWith("swd#wpdbusenum#", StringComparison.Ordinal);
    }

    private static bool LooksLikePhone(string friendlyName, string instanceId)
    {
        // Hard exclude: USBSTOR\DISK&...&PROD_FLASH_DRIVE is a USB flash stick, not a
        // phone — even when VID is Samsung (Samsung makes both phones AND flash
        // drives under VID_04E8). Without this exclusion the operator at Sơn La saw
        // Samsung Flash Drives ("WinInstall", "NHV-BOOT") classified as phones.
        if (instanceId.Contains("usbstor", StringComparison.OrdinalIgnoreCase)
            && instanceId.Contains("flash_drive", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        // Same for generic "DISK&" enumerator path — those are mass-storage USB
        // sticks/SSDs, not MTP phones.
        if (instanceId.Contains("usbstor#disk", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (Matches(friendlyName) || Matches(instanceId))
        {
            return true;
        }
        // Apple's USB VID is 05AC — every iPhone/iPad/iPod surfaces with that prefix.
        if (instanceId.Contains("VID_05AC", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        // Samsung mobile USB VID = 04E8 BUT also used by Samsung flash drives + monitors
        // + printers. Only flag as phone when path ALSO carries an MTP/PTP marker —
        // those are mobile-only personalities.
        if (instanceId.Contains("VID_04E8", StringComparison.OrdinalIgnoreCase)
            && (instanceId.Contains("MS_COMP_MTP", StringComparison.OrdinalIgnoreCase)
                || instanceId.Contains("MS_COMP_PTP", StringComparison.OrdinalIgnoreCase)
                || instanceId.Contains("ANDROID", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
        // Google (Pixel) = 18D1, Huawei = 12D1, Xiaomi = 2717, OPPO = 22D9, Vivo = 2D95.
        string[] phoneVids = { "VID_18D1", "VID_12D1", "VID_2717", "VID_22D9", "VID_2D95" };
        foreach (var v in phoneVids)
        {
            if (instanceId.Contains(v, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool Matches(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }
        var lower = text.ToLowerInvariant();
        foreach (var token in PhoneTokens)
        {
            if (lower.Contains(token, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }
}
