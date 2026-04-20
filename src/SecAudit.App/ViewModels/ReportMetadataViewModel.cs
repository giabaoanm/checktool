using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecAudit.Core.Services;

namespace SecAudit.App.ViewModels;

/// <summary>
/// Hỗ trợ popup "Thông tin biên bản" hiện trước khi xuất báo cáo. Mọi trường
/// tùy chọn — trống sẽ render thành dấu chấm trong báo cáo. Toàn bộ giá trị
/// persist vào <c>%LOCALAPPDATA%\SecAudit\report-metadata.json</c> qua
/// <see cref="ReportSettingsStore"/> để lần sau mở sẵn.
/// </summary>
public sealed partial class ReportMetadataViewModel : ObservableObject
{
    [ObservableProperty] private string _orgLine1 = string.Empty;
    [ObservableProperty] private string _orgLine2 = string.Empty;
    [ObservableProperty] private string _place = string.Empty;
    [ObservableProperty] private bool _autoDate = true;
    [ObservableProperty] private string _legalBasis = string.Empty;
    [ObservableProperty] private string _inspectionLocation = string.Empty;
    [ObservableProperty] private string _inspectionTeam = string.Empty;
    [ObservableProperty] private string _auditedUnitDetail = string.Empty;
    [ObservableProperty] private string _auditedUnit = string.Empty;
    [ObservableProperty] private string _teamLeader = string.Empty;
    [ObservableProperty] private string _teamMember = string.Empty;
    [ObservableProperty] private string _recorder = string.Empty;

    /// <summary>
    /// Set true by the dialog's OK button handler. The caller inspects this after
    /// <c>ShowDialog()</c> returns to decide whether to proceed with the export.
    /// </summary>
    public bool Confirmed { get; set; }

    public void LoadFrom(ReportSettings s)
    {
        OrgLine1 = s.OrgLine1;
        OrgLine2 = s.OrgLine2;
        Place = s.Place;
        AutoDate = s.AutoDate;
        LegalBasis = s.LegalBasis;
        InspectionLocation = s.InspectionLocation;
        InspectionTeam = s.InspectionTeam;
        AuditedUnitDetail = s.AuditedUnitDetail;
        AuditedUnit = s.AuditedUnit;
        TeamLeader = s.TeamLeader;
        TeamMember = s.TeamMember;
        Recorder = s.Recorder;
    }

    public ReportSettings ToSettings()
    {
        return new ReportSettings
        {
            OrgLine1 = OrgLine1 ?? string.Empty,
            OrgLine2 = OrgLine2 ?? string.Empty,
            Place = Place ?? string.Empty,
            AutoDate = AutoDate,
            LegalBasis = LegalBasis ?? string.Empty,
            InspectionLocation = InspectionLocation ?? string.Empty,
            InspectionTeam = InspectionTeam ?? string.Empty,
            AuditedUnitDetail = AuditedUnitDetail ?? string.Empty,
            AuditedUnit = AuditedUnit ?? string.Empty,
            TeamLeader = TeamLeader ?? string.Empty,
            TeamMember = TeamMember ?? string.Empty,
            Recorder = Recorder ?? string.Empty
        };
    }

    /// <summary>
    /// Xóa mọi trường và tắt AutoDate → báo cáo xuất ra toàn bộ là dấu chấm để
    /// người dùng điền tay hoàn toàn (tương đương form trắng in sẵn).
    /// </summary>
    [RelayCommand]
    private void ClearAll()
    {
        OrgLine1 = string.Empty;
        OrgLine2 = string.Empty;
        Place = string.Empty;
        AutoDate = false;
        LegalBasis = string.Empty;
        InspectionLocation = string.Empty;
        InspectionTeam = string.Empty;
        AuditedUnitDetail = string.Empty;
        AuditedUnit = string.Empty;
        TeamLeader = string.Empty;
        TeamMember = string.Empty;
        Recorder = string.Empty;
    }
}
