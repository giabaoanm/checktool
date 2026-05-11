using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Standalone IR module that analyses an extracted Linux rootfs OR an OCI image
/// bundle (auto-extracts first) for ransomware / intrusion patterns. Activated
/// only when <c>ScanContext.Options["linux-incident.settings"]</c> contains a
/// JSON-serialised <see cref="LinuxIncidentSettings"/>; under "Run all modules"
/// it no-ops with <c>Succeeded=true</c>.
/// </summary>
public sealed class LinuxIncidentModule : IAuditModule
{
    public const string OptionKey = "linux-incident.settings";
    public const string SharedResultKey = "linux-incident.result";

    private readonly LinuxIncidentAnalyzer _analyzer;
    private readonly OciImageExtractor _extractor;
    private readonly ILogger<LinuxIncidentModule> _logger;

    public LinuxIncidentModule(
        LinuxIncidentAnalyzer analyzer,
        OciImageExtractor extractor,
        ILogger<LinuxIncidentModule> logger)
    {
        _analyzer = analyzer;
        _extractor = extractor;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "linux-incident",
        DisplayName: "Ứng cứu sự cố Linux (rootfs / OCI image)",
        Description: "Phân tích rootfs hoặc OCI image bundle: SSH brute-force, "
                     + "sudoers misconfig, cron persistence, ransom note, file mã hoá, IOC sweep.",
        Category: "Ứng cứu sự cố",
        Version: "1.0.0",
        RequiresAdministrator: false,
        IsSensitive: true,
        DisplayOrder: 67);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(progress);
        var started = DateTimeOffset.UtcNow;

        if (!context.TryGetOption(OptionKey, out var json) || string.IsNullOrWhiteSpace(json))
        {
            return Task.FromResult(Done(started, Array.Empty<object>(), null));
        }

        LinuxIncidentSettings settings;
        try
        {
            settings = JsonSerializer.Deserialize<LinuxIncidentSettings>(json) ?? new LinuxIncidentSettings();
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Invalid linux incident settings");
            return Task.FromResult(Done(started, Array.Empty<object>(),
                "Cấu hình linux incident không hợp lệ.", succeeded: false));
        }

        if (string.IsNullOrWhiteSpace(settings.Path))
        {
            return Task.FromResult(Done(started, Array.Empty<object>(), null));
        }

        var asset = string.IsNullOrWhiteSpace(settings.Asset)
            ? context.MachineName
            : settings.Asset;
        var findings = new List<object>();
        string? tempExtractDir = null;
        try
        {
            var rootfs = settings.Path;

            if (OciImageExtractor.LooksLikeOciBundle(rootfs))
            {
                progress.Report(new ProgressUpdate(Metadata.Id,
                    "Đang giải nén OCI image bundle vào thư mục tạm...", 5));
                tempExtractDir = Path.Combine(Path.GetTempPath(),
                    "secaudit-oci-" + Guid.NewGuid().ToString("N")[..12]);
                _extractor.Extract(rootfs, tempExtractDir, cancellationToken);
                rootfs = tempExtractDir;
            }
            // Single-file archive (.tar / .tar.gz / .tgz / .zip): auto-extract before scan.
            else if (File.Exists(rootfs)
                && ArchiveExtractor.Detect(rootfs) is var kind
                && kind != ArchiveExtractor.ArchiveKind.None)
            {
                progress.Report(new ProgressUpdate(Metadata.Id,
                    $"Đang giải nén archive ({kind}) vào thư mục tạm...", 5));
                tempExtractDir = Path.Combine(Path.GetTempPath(),
                    "secaudit-arc-" + Guid.NewGuid().ToString("N")[..12]);
                ArchiveExtractor.Extract(rootfs, tempExtractDir, cancellationToken);
                rootfs = tempExtractDir;
            }

            if (!Directory.Exists(rootfs))
            {
                findings.Add(Finding.Create(
                    id: "LIN-INPUT-INVALID",
                    title: "Đường dẫn rootfs không tồn tại",
                    severity: Severity.Medium,
                    category: "Linux Incident",
                    asset: asset,
                    evidence: $"Path: {rootfs}",
                    remediation: "Kiểm tra lại đường dẫn; nếu là OCI bundle, đảm bảo có "
                               + "oci-layout + index.json + blobs/sha256/."));
                return Task.FromResult(Done(started, findings, null));
            }

            progress.Report(new ProgressUpdate(Metadata.Id, "Đang phân tích rootfs...", 25));
            var result = _analyzer.Analyze(rootfs, asset, cancellationToken);
            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Hoàn tất — quét {result.FilesScanned} tệp, {result.Findings.Count} finding, "
                + $"{result.ExtractedIocs.Count} IOC.", 100));

            findings.AddRange(result.Findings);

            // Sanity check: scanned 0 files? Surface a Medium finding so the
            // analyst knows the tool didn't silently see "nothing".
            if (result.FilesScanned == 0)
            {
                findings.Add(Finding.Create(
                    id: "LIN-EMPTY-SCAN",
                    title: "Đã quét nhưng không tìm thấy artifact Linux quen thuộc",
                    severity: Severity.Medium,
                    category: "Linux Incident",
                    asset: asset,
                    evidence: $"Rootfs: {rootfs}\nKhông thấy /var/log, /etc/sudoers, /var/spool/cron, /home, /root/...",
                    remediation: "Kiểm tra lại định dạng input — có thể đây không phải Linux rootfs. "
                               + "Nếu là disk image (.img / .vhdx / .vmdk), hãy mount trước rồi point lại."));
            }

            context.SetShared(SharedResultKey, result);
            return Task.FromResult(Done(started, findings, null));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Linux incident analysis failed");
            findings.Add(Finding.Create(
                id: "LIN-ANALYSIS-FAILED",
                title: "Phân tích Linux incident thất bại",
                severity: Severity.Medium,
                category: "Linux Incident",
                asset: asset,
                evidence: ex.Message,
                remediation: "Kiểm tra log SecAudit để biết chi tiết; thử lại với rootfs đã extract sẵn."));
            return Task.FromResult(Done(started, findings, ex.Message, succeeded: false));
        }
        finally
        {
            if (tempExtractDir is not null && settings.CleanupAfterScan && Directory.Exists(tempExtractDir))
            {
                try { Directory.Delete(tempExtractDir, recursive: true); }
                catch { /* best effort */ }
            }
        }
    }

    private ModuleResult Done(
        DateTimeOffset started,
        IReadOnlyList<object> findings,
        string? reason,
        bool succeeded = true)
        => new()
        {
            ModuleId = Metadata.Id,
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            Succeeded = succeeded,
            FailureReason = reason,
            Findings = findings
        };
}

public sealed record LinuxIncidentSettings
{
    /// <summary>Either an extracted Linux rootfs path OR an OCI image bundle directory.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Asset label for findings; defaults to <c>ScanContext.MachineName</c>.</summary>
    public string Asset { get; init; } = string.Empty;

    /// <summary>If true, delete the temp-extracted OCI rootfs after analysis (default: false — keep for evidence).</summary>
    public bool CleanupAfterScan { get; init; }
}
