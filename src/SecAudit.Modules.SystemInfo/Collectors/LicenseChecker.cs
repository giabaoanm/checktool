using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Wmi;
using SecAudit.Modules.SystemInfo.Models;

namespace SecAudit.Modules.SystemInfo.Collectors;

[SupportedOSPlatform("windows")]
public sealed class LicenseChecker
{
    // Application IDs exposed by Software Protection Platform.
    // Windows (Core / Client OS): 55c92734-d682-4d71-983e-d6ec3f16059f
    // Office:                     59a52881-a989-479d-af46-f275c6370663
    internal const string WindowsAppId = "55c92734-d682-4d71-983e-d6ec3f16059f";
    internal const string OfficeAppId = "59a52881-a989-479d-af46-f275c6370663";

    private readonly IWmiQuery _wmi;
    private readonly ILogger<LicenseChecker> _logger;

    public LicenseChecker(IWmiQuery wmi, ILogger<LicenseChecker> logger)
    {
        _wmi = wmi;
        _logger = logger;
    }

    public LicenseInfo CollectWindowsLicense()
    {
        try
        {
            var products = _wmi.Query(@"\\.\ROOT\CIMV2",
                $"SELECT Name, Description, LicenseStatus, PartialProductKey, KeyManagementServiceMachine " +
                $"FROM SoftwareLicensingProduct " +
                $"WHERE ApplicationID = '{WindowsAppId}' AND PartialProductKey IS NOT NULL").ToList();

            var first = products.FirstOrDefault();
            if (first is null)
            {
                return new LicenseInfo(
                    Product: "Windows",
                    LicenseStatusText: "Unknown (no licensed product reported)",
                    LicenseStatus: -1,
                    Description: string.Empty,
                    PartialProductKey: null,
                    KmsServer: null,
                    IsGenuine: false);
            }

            var status = ParseStatus(first);
            return new LicenseInfo(
                Product: Str(first, "Name") ?? "Windows",
                LicenseStatusText: StatusText(status),
                LicenseStatus: status,
                Description: Str(first, "Description") ?? string.Empty,
                PartialProductKey: Str(first, "PartialProductKey"),
                KmsServer: Str(first, "KeyManagementServiceMachine"),
                IsGenuine: status == 1);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Windows license query failed");
            return new LicenseInfo("Windows", "Query failed: " + ex.Message, -1, string.Empty, null, null, false);
        }
    }

    public IReadOnlyList<LicenseInfo> CollectOfficeLicenses()
    {
        var list = new List<LicenseInfo>();
        try
        {
            var products = _wmi.Query(@"\\.\ROOT\CIMV2",
                $"SELECT Name, Description, LicenseStatus, PartialProductKey, KeyManagementServiceMachine " +
                $"FROM SoftwareLicensingProduct " +
                $"WHERE ApplicationID = '{OfficeAppId}' AND PartialProductKey IS NOT NULL");
            foreach (var p in products)
            {
                var status = ParseStatus(p);
                list.Add(new LicenseInfo(
                    Product: Str(p, "Name") ?? "Office",
                    LicenseStatusText: StatusText(status),
                    LicenseStatus: status,
                    Description: Str(p, "Description") ?? string.Empty,
                    PartialProductKey: Str(p, "PartialProductKey"),
                    KmsServer: Str(p, "KeyManagementServiceMachine"),
                    IsGenuine: status == 1));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Office license query failed");
        }
        return list;
    }

    // Documented LicenseStatus values from SoftwareLicensingProduct.
    internal static string StatusText(int status) => status switch
    {
        0 => "Unlicensed",
        1 => "Licensed",
        2 => "Out-of-Box grace",
        3 => "Out-of-Tolerance grace",
        4 => "Non-genuine grace",
        5 => "Notification",
        6 => "Extended grace",
        _ => "Unknown"
    };

    private static int ParseStatus(IReadOnlyDictionary<string, object?> row)
    {
        if (row.TryGetValue("LicenseStatus", out var v) && v is not null
            && int.TryParse(v.ToString(), out var i))
        {
            return i;
        }
        return -1;
    }

    private static string? Str(IReadOnlyDictionary<string, object?> dict, string key)
        => dict.TryGetValue(key, out var v) ? v?.ToString() : null;
}
