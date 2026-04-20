namespace SecAudit.Reporting.Services;

/// <summary>
/// Maps internal module IDs (kebab-case English) to formal Vietnamese section
/// titles used in the printed "BIÊN BẢN GHI NHẬN" report.
///
/// Unknown IDs fall back to the raw ID so a new module shows up immediately
/// without breaking the report — translators can extend the map later.
/// </summary>
public static class ModuleNameTranslator
{
    private static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["system-info"]    = "Thông tin hệ thống & bản quyền",
        ["hardening"]      = "Cấu hình tăng cường bảo mật (CIS)",
        ["patch-cve"]      = "Bản vá & lỗ hổng (CVE)",
        ["lan-scanner"]    = "Quét mạng nội bộ (LAN)",
        ["remote-access"]  = "Truy cập từ xa & dấu hiệu duy trì",
        ["credential-audit"] = "Kiểm tra thông tin xác thực",
        ["hello"]          = "Module mẫu (demo)",
    };

    public static string Translate(string moduleId)
        => Map.TryGetValue(moduleId, out var vi) ? vi : moduleId;
}
