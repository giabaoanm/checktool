using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecAudit.Core.Services;

/// <summary>
/// Metadata điền vào "BIÊN BẢN GHI NHẬN". Mọi trường đều tùy chọn — trường để trống
/// sẽ render thành các dấu chấm (dòng kẻ để điền tay sau khi in).
///
/// Persist vào %LOCALAPPDATA%\SecAudit\report-metadata.json để lần sau mở dialog
/// các giá trị cũ đã sẵn, admin chỉ cần chỉnh khác biệt nếu có.
/// </summary>
public sealed class ReportSettings
{
    // ===== Header (top-left, 2 dòng theo chuẩn biên bản Công an VN) =====
    /// <summary>
    /// Dòng 1 (đơn vị cấp trên), Times New Roman 13pt, in hoa không đậm.
    /// Ví dụ: "CÔNG AN TỈNH SƠN LA".
    /// </summary>
    public string OrgLine1 { get; set; } = string.Empty;

    /// <summary>
    /// Dòng 2 (đơn vị cấp dưới / đơn vị soạn thảo), Times New Roman 13pt, in hoa đậm.
    /// Ví dụ: "TỔ KIỂM TRA" hoặc "PHÒNG AN NINH MẠNG".
    /// </summary>
    public string OrgLine2 { get; set; } = string.Empty;

    /// <summary>
    /// Địa điểm xuất hiện trong dòng ngày tháng (vd "Hà Nội"). Nếu trống,
    /// toàn bộ dòng "..., ngày ... tháng ... năm ..." sẽ là dấu chấm.
    /// </summary>
    public string Place { get; set; } = string.Empty;

    /// <summary>
    /// Nếu true → điền ngày/tháng/năm và giờ/phút từ <c>GeneratedAt</c>.
    /// Nếu false → ngày giờ in ra cũng thành dấu chấm để điền tay.
    /// </summary>
    public bool AutoDate { get; set; } = true;

    // ===== Mở đầu =====
    /// <summary>
    /// "Căn cứ ... ." — cơ sở pháp lý của cuộc kiểm tra (quyết định, kế hoạch...).
    /// Hỗ trợ nhiều dòng (mỗi dòng một căn cứ).
    /// </summary>
    public string LegalBasis { get; set; } = string.Empty;

    /// <summary>
    /// Địa điểm kiểm tra ("tại: ..."). Ví dụ "Phòng máy chủ, Tầng 5, Tòa nhà A".
    /// </summary>
    public string InspectionLocation { get; set; } = string.Empty;

    // ===== Thành phần =====
    /// <summary>
    /// Danh sách thành viên tổ kiểm tra (mỗi dòng: họ tên - chức vụ).
    /// </summary>
    public string InspectionTeam { get; set; } = string.Empty;

    /// <summary>
    /// Thông tin đơn vị được kiểm tra (mỗi dòng một trường: tên, địa chỉ, đại diện...).
    /// </summary>
    public string AuditedUnitDetail { get; set; } = string.Empty;

    // ===== Chữ ký =====
    /// <summary>
    /// Họ tên người đại diện đơn vị được kiểm tra (ô ký dưới góc trái).
    /// </summary>
    public string AuditedUnit { get; set; } = string.Empty;

    /// <summary>
    /// Họ tên tổ trưởng tổ kiểm tra (ô ký dưới góc phải trên).
    /// </summary>
    public string TeamLeader { get; set; } = string.Empty;

    /// <summary>
    /// Họ tên cán bộ tham gia (ô ký dưới góc trái dưới).
    /// </summary>
    public string TeamMember { get; set; } = string.Empty;

    /// <summary>
    /// Họ tên cán bộ lập biên bản (ô ký dưới góc phải dưới).
    /// </summary>
    public string Recorder { get; set; } = string.Empty;

    public ReportSettings Clone()
    {
        return new ReportSettings
        {
            OrgLine1 = OrgLine1,
            OrgLine2 = OrgLine2,
            Place = Place,
            AutoDate = AutoDate,
            LegalBasis = LegalBasis,
            InspectionLocation = InspectionLocation,
            InspectionTeam = InspectionTeam,
            AuditedUnitDetail = AuditedUnitDetail,
            AuditedUnit = AuditedUnit,
            TeamLeader = TeamLeader,
            TeamMember = TeamMember,
            Recorder = Recorder
        };
    }
}

/// <summary>
/// Đọc/ghi <see cref="ReportSettings"/> vào file JSON dưới
/// %LOCALAPPDATA%\SecAudit\report-metadata.json. Ghi atomic (tempfile + rename)
/// để không hỏng file nếu app crash giữa chừng.
/// </summary>
public sealed class ReportSettingsStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string FilePath { get; }

    public ReportSettingsStore()
    {
        var folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAudit");
        FilePath = Path.Combine(folder, "report-metadata.json");
    }

    public ReportSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return new ReportSettings();
            }

            using var stream = File.OpenRead(FilePath);
            var loaded = JsonSerializer.Deserialize<ReportSettings>(stream, Options);
            return loaded ?? new ReportSettings();
        }
        catch
        {
            // Corrupt/unreadable file — fall back to defaults rather than crashing export.
            return new ReportSettings();
        }
    }

    public void Save(ReportSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var folder = Path.GetDirectoryName(FilePath)!;
        Directory.CreateDirectory(folder);

        var temp = FilePath + ".tmp";
        using (var stream = File.Create(temp))
        {
            JsonSerializer.Serialize(stream, settings, Options);
        }

        if (File.Exists(FilePath))
        {
            File.Replace(temp, FilePath, destinationBackupFileName: null);
        }
        else
        {
            File.Move(temp, FilePath);
        }
    }
}
