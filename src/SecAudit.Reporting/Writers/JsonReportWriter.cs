using System.Text.Json;
using System.Text.Json.Serialization;
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
/// </summary>
public sealed class JsonReportWriter : IReportWriter
{
    private const int SchemaVersion = 5;

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
                biosSerial = data.Device.BiosSerial,
                totalRam = data.Device.TotalRam,
                operatingSystem = data.Device.OperatingSystem,
                networks = data.Device.NetworkAddresses
            },
            score = new { value = data.Score.Value, band = data.Score.Band },
            severityCounts = data.SeverityCounts.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value),
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
                    f.DetectedAt
                })
            }),
            appliedActions = data.AppliedActions,
            recommendations = data.Recommendations
        };

        await using var stream = File.Create(outputPath);
        await JsonSerializer.SerializeAsync(stream, envelope, Options, ct).ConfigureAwait(false);
    }
}
