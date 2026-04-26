using SecAudit.Core.Models;
using SecAudit.Core.Services;

namespace SecAudit.Reporting.Models;

/// <summary>
/// Snapshot passed to every report writer. The formal Vietnamese "BIÊN BẢN
/// GHI NHẬN" form has its header (đơn vị, ngày, căn cứ, thành phần) and
/// signature block rendered from <see cref="Metadata"/>; any field left empty
/// there prints as dotted blanks the inspector fills by hand after printing.
///
/// Data content (Section II) is always dynamic:
///   1. Thông tin thiết bị kiểm tra       → <see cref="Device"/>
///   1b. Trạng thái bản quyền (optional)   → <see cref="License"/>
///   1c. Tổng hợp bản vá (optional)        → <see cref="Patch"/>
///   1d. Phạm vi quét (optional)           → <see cref="Scope"/>
///   2..N. Per-module findings            → <see cref="ByModule"/>
///   (optional) Nội dung đã xử lý khắc phục → <see cref="AppliedActions"/>
///   (optional) Khuyến nghị                → <see cref="Recommendations"/>
///
/// <see cref="License"/>, <see cref="Patch"/>, <see cref="Scope"/> are nullable
/// so callers that didn't run the producing module (e.g. log-forensics-only
/// export) can pass null and the writers omit those sections.
/// </summary>
public sealed record ReportData(
    string AssetName,
    DateTimeOffset GeneratedAt,
    RiskScore Score,
    IReadOnlyDictionary<string, IReadOnlyList<Finding>> ByModule,
    IReadOnlyDictionary<Severity, int> SeverityCounts,
    DeviceProfile Device,
    LicenseSummary? License,
    PatchSummary? Patch,
    ScanScope? Scope,
    IReadOnlyList<AppliedAction> AppliedActions,
    IReadOnlyList<Recommendation> Recommendations,
    ReportSettings Metadata)
{
    public IEnumerable<Finding> AllFindings => ByModule.Values.SelectMany(x => x);
    public int TotalFindings => ByModule.Values.Sum(x => x.Count);
}
