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
///   2..N. Per-module findings            → <see cref="ByModule"/>
///   (optional) Nội dung đã xử lý khắc phục → <see cref="AppliedActions"/>
///   (optional) Khuyến nghị                → <see cref="Recommendations"/>
/// </summary>
public sealed record ReportData(
    string AssetName,
    DateTimeOffset GeneratedAt,
    RiskScore Score,
    IReadOnlyDictionary<string, IReadOnlyList<Finding>> ByModule,
    IReadOnlyDictionary<Severity, int> SeverityCounts,
    DeviceProfile Device,
    IReadOnlyList<AppliedAction> AppliedActions,
    IReadOnlyList<Recommendation> Recommendations,
    ReportSettings Metadata)
{
    public IEnumerable<Finding> AllFindings => ByModule.Values.SelectMany(x => x);
    public int TotalFindings => ByModule.Values.Sum(x => x.Count);
}
