using System.Globalization;
using System.Reflection;
using System.Text;
using Scriban;
using SecAudit.Core.Models;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.Reporting.Writers;

/// <summary>
/// Renders the embedded Scriban template against a flat anonymous model. The
/// "BIÊN BẢN GHI NHẬN" template has hard-coded blanks (dotted lines) for header,
/// dates, legal basis and signatures — only Section II (Kết quả kiểm tra) is
/// data-driven.
/// </summary>
public sealed class HtmlReportWriter : IReportWriter
{
    private const string TemplateResource = "SecAudit.Reporting.Templates.report.html.sbn";

    public string Extension => "html";
    public string DisplayName => "HTML";

    public async Task WriteAsync(ReportData data, string outputPath, CancellationToken ct)
    {
        var templateText = LoadTemplate();
        var template = Template.Parse(templateText, TemplateResource);
        if (template.HasErrors)
        {
            throw new InvalidOperationException(
                "Report template has errors: " + string.Join("; ", template.Messages));
        }

        var m = data.Metadata;
        var gen = data.GeneratedAt.LocalDateTime;
        bool hasPlace = !string.IsNullOrWhiteSpace(m.Place);
        bool showDate = m.AutoDate;

        var meta = new
        {
            // Header (top-left, 2 dòng theo chuẩn biên bản Công an VN)
            org_line_1 = m.OrgLine1,
            org_line_2 = m.OrgLine2,
            has_org_line_1 = !string.IsNullOrWhiteSpace(m.OrgLine1),
            has_org_line_2 = !string.IsNullOrWhiteSpace(m.OrgLine2),
            has_any_org_line = !string.IsNullOrWhiteSpace(m.OrgLine1) || !string.IsNullOrWhiteSpace(m.OrgLine2),

            // Dòng ngày tháng năm (góc phải)
            place = m.Place,
            has_place = hasPlace,
            auto_date = showDate,
            day = showDate ? gen.Day.ToString(CultureInfo.InvariantCulture) : string.Empty,
            month = showDate ? gen.Month.ToString(CultureInfo.InvariantCulture) : string.Empty,
            year = showDate ? gen.Year.ToString(CultureInfo.InvariantCulture) : string.Empty,
            hour = showDate ? gen.Hour.ToString("D2", CultureInfo.InvariantCulture) : string.Empty,
            minute = showDate ? gen.Minute.ToString("D2", CultureInfo.InvariantCulture) : string.Empty,

            // Body
            legal_basis_lines = SplitLines(m.LegalBasis),
            has_legal_basis = !string.IsNullOrWhiteSpace(m.LegalBasis),
            inspection_location_lines = SplitLines(m.InspectionLocation),
            has_inspection_location = !string.IsNullOrWhiteSpace(m.InspectionLocation),
            inspection_team_lines = SplitLines(m.InspectionTeam),
            has_inspection_team = !string.IsNullOrWhiteSpace(m.InspectionTeam),
            audited_unit_detail_lines = SplitLines(m.AuditedUnitDetail),
            has_audited_unit_detail = !string.IsNullOrWhiteSpace(m.AuditedUnitDetail),

            // Signatures
            audited_unit = m.AuditedUnit,
            team_leader = m.TeamLeader,
            team_member = m.TeamMember,
            recorder = m.Recorder
        };

        var model = new
        {
            asset = data.AssetName,
            total = data.TotalFindings,
            meta = meta,

            device = new
            {
                computer_name = data.Device.ComputerName,
                cpu = data.Device.Cpu,
                bios_serial = data.Device.BiosSerial,
                total_ram = data.Device.TotalRam,
                operating_system = data.Device.OperatingSystem,
                networks = data.Device.NetworkAddresses.Select(n => new
                {
                    interface_name = n.InterfaceName,
                    mac = n.MacAddress,
                    ipv4 = n.IPv4,
                    ipv6 = n.IPv6 ?? string.Empty
                }).ToArray()
            },

            modules = data.ByModule.Select(kv => new
            {
                id = kv.Key,
                display_name = ModuleNameTranslator.Translate(kv.Key),
                count = kv.Value.Count,
                findings = kv.Value
                    .OrderByDescending(f => (int)f.Severity)
                    .Select(f => new
                    {
                        severity = f.Severity.ToString(),
                        id = f.Id,
                        title = f.Title,
                        asset = f.Asset,
                        evidence = f.Evidence,
                        remediation = f.Remediation
                    }).ToArray()
            }).ToArray(),

            applied = data.AppliedActions.Select(a => new
            {
                finding_id = a.FindingId,
                title = a.ActionTitle,
                status_text = a.Succeeded ? "Thành công" : "Thất bại",
                css = a.Succeeded ? "applied-ok" : "applied-fail",
                message = a.Message,
                reboot = a.RebootRequired ? "Có" : "Không",
                applied_at = a.AppliedAt.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture)
            }).ToArray(),

            recommendations = data.Recommendations.Select(r => new
            {
                finding_id = r.FindingId,
                title = r.Title,
                severity = r.Severity,
                guidance = r.Guidance
            }).ToArray()
        };

        var rendered = await template.RenderAsync(model, member => member.Name).ConfigureAwait(false);
        await File.WriteAllTextAsync(outputPath, rendered, new UTF8Encoding(false), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Chuẩn hóa textarea thành mảng dòng. Windows CRLF / Unix LF / Mac CR đều được
    /// tách; dòng trống ở đầu/cuối bị loại (dòng trống ở giữa giữ lại để người dùng
    /// tự chủ spacing).
    /// </summary>
    private static string[] SplitLines(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }
        var normalized = value.Replace("\r\n", "\n").Replace('\r', '\n');
        var parts = normalized.Split('\n');
        // Trim leading/trailing blank lines but keep internal blanks.
        int start = 0;
        int end = parts.Length - 1;
        while (start <= end && string.IsNullOrWhiteSpace(parts[start])) { start++; }
        while (end >= start && string.IsNullOrWhiteSpace(parts[end])) { end--; }
        if (start > end)
        {
            return Array.Empty<string>();
        }
        var result = new string[end - start + 1];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = parts[start + i];
        }
        return result;
    }

    private static string LoadTemplate()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(TemplateResource)
            ?? throw new InvalidOperationException("Missing embedded template: " + TemplateResource);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
