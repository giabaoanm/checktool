using System.Text.Json;
using System.Text.Json.Serialization;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using SecAudit.Reporting.Models;
using SecAudit.Reporting.Services;

namespace SecAudit.Reporting.Writers;

/// <summary>
/// Stable, machine-readable export. Schema version goes in the top-level envelope so
/// downstream SIEM/dashboard consumers can detect breaking changes.
///
/// v4: reset for the "BIÊN BẢN" layout — header/signature fields removed because the
/// printable template has them blank by design. Only Section II content is data.
/// v5: optional ReportSettings metadata (org name, signers, legal basis, ...) so SIEM
/// consumers can correlate a report with the inspection record it belongs to.
/// v6 (2026-04-25): expanded `device` (CPU cores, BIOS vendor/date, disks, TPM,
/// Secure Boot), and added top-level `license`, `patchSummary`, `scope` envelopes
/// so consumers see baseline state regardless of whether a finding fired.
/// v7 (2026-04-29): clarified score semantics. `score` is security posture
/// (higher is better); `risk` is inverse risk (higher is worse).
/// v8 (2026-05-05): added operator triage summary plus per-finding explanation,
/// confidence, action group, scenario and handling steps.
/// </summary>
public sealed class JsonReportWriter : IReportWriter
{
    private const int SchemaVersion = 8;

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public string Extension => "json";
    public string DisplayName => "JSON";

    public async Task WriteAsync(ReportData data, string outputPath, CancellationToken ct)
    {
        var envelope = new
        {
            schemaVersion = SchemaVersion,
            generator = "SecAudit",
            asset = data.AssetName,
            generatedAt = data.GeneratedAt,
            metadata = new
            {
                orgLine1 = data.Metadata.OrgLine1,
                orgLine2 = data.Metadata.OrgLine2,
                place = data.Metadata.Place,
                autoDate = data.Metadata.AutoDate,
                legalBasis = data.Metadata.LegalBasis,
                inspectionLocation = data.Metadata.InspectionLocation,
                inspectionTeam = data.Metadata.InspectionTeam,
                auditedUnitDetail = data.Metadata.AuditedUnitDetail,
                auditedUnit = data.Metadata.AuditedUnit,
                teamLeader = data.Metadata.TeamLeader,
                teamMember = data.Metadata.TeamMember,
                recorder = data.Metadata.Recorder
            },
            device = new
            {
                computerName = data.Device.ComputerName,
                cpu = data.Device.Cpu,
                cpuCores = data.Device.CpuCores,
                cpuLogicalProcessors = data.Device.CpuLogicalProcessors,
                biosSerial = data.Device.BiosSerial,
                biosVendor = data.Device.BiosVendor,
                biosVersion = data.Device.BiosVersion,
                biosReleaseDate = data.Device.BiosReleaseDate,
                totalRam = data.Device.TotalRam,
                operatingSystem = data.Device.OperatingSystem,
                tpmPresent = data.Device.TpmPresent,
                tpmSpecVersion = data.Device.TpmSpecVersion,
                secureBootEnabled = data.Device.SecureBootEnabled,
                disks = data.Device.Disks,
                networks = data.Device.NetworkAddresses
            },
            license = data.License,
            patchSummary = data.Patch,
            scope = data.Scope,
            score = new
            {
                value = data.Score.Value,
                band = data.Score.Band,
                scale = "security-posture",
                higherIsBetter = true
            },
            risk = new
            {
                value = 100 - data.Score.Value,
                band = RiskBandFromSecurityScore(data.Score.Value),
                scale = "risk",
                higherIsWorse = true
            },
            severityCounts = data.SeverityCounts.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value),
            operatorTriage = new
            {
                actionGroups = CountTriage(data.AllFindings, t => t.ActionGroup),
                scenarios = CountTriage(data.AllFindings, t => t.Scenario),
                guide = new[]
                {
                    "Cần xử lý ngay: ưu tiên cô lập/chặn/khắc phục sau khi lưu bằng chứng.",
                    "Cần xử lý: khắc phục theo chính sách hoặc cấu hình trong kế hoạch gần nhất.",
                    "Cần xem lại: đối chiếu baseline, người dùng và log trước khi kết luận.",
                    "Có thể bỏ qua/Thông tin: giữ trong triage-all để tham khảo, không coi là IOC độc hại."
                }
            },
            modules = data.ByModule.Select(kv => new
            {
                id = kv.Key,
                displayName = ModuleNameTranslator.Translate(kv.Key),
                findingCount = kv.Value.Count,
                findings = kv.Value.Select(f => new
                {
                    f.Id,
                    f.Title,
                    severity = f.Severity.ToString(),
                    f.CvssScore,
                    f.Category,
                    f.Asset,
                    f.Evidence,
                    f.Remediation,
                    f.References,
                    f.DetectedAt,
                    triage = MapTriage(FindingTriageInterpreter.Interpret(f))
                })
            }),
            appliedActions = data.AppliedActions,
            recommendations = data.Recommendations
        };

        await using var stream = File.Create(outputPath);
        await JsonSerializer.SerializeAsync(stream, envelope, Options, ct).ConfigureAwait(false);
    }

    private static string RiskBandFromSecurityScore(int securityScore)
    {
        var risk = 100 - Math.Clamp(securityScore, 0, 100);
        return risk switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 40 => "Medium",
            >= 20 => "Low",
            _ => "Minimal"
        };
    }

    private static object MapTriage(FindingTriage triage) => new
    {
        actionGroup = triage.ActionGroup,
        confidence = triage.Confidence,
        scenario = triage.Scenario,
        explanation = triage.Explanation,
        steps = triage.Steps
    };

    private static object[] CountTriage(
        IEnumerable<Finding> findings,
        Func<FindingTriage, string> selector)
        => findings
            .Select(f => selector(FindingTriageInterpreter.Interpret(f)))
            .GroupBy(value => value, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => (object)new { name = g.Key, count = g.Count() })
            .ToArray();
}
