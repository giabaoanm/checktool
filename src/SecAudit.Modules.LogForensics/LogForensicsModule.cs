using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Services;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics;

/// <summary>
/// Iteration 6 — Log forensics / evidence collection. This module is **interactive-only**:
/// it only runs when the shell/CLI writes a serialized <see cref="ForensicsSettings"/> blob
/// into <c>ScanContext.Options["log-forensics.settings"]</c>. Under a normal "Run all modules"
/// it no-ops (returns zero findings, <c>Succeeded=true</c>) so it stays out of the way.
///
/// All user-visible output is in Vietnamese to match the rest of the suite.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LogForensicsModule : IAuditModule
{
    public const string OptionKey = "log-forensics.settings";

    private readonly LogForensicsEngine _engine;
    private readonly ILogger<LogForensicsModule> _log;

    public LogForensicsModule(LogForensicsEngine engine, ILogger<LogForensicsModule> log)
    {
        _engine = engine;
        _log = log;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "log-forensics",
        DisplayName: "Phân tích nhật ký / Log Forensics",
        Description: "Truy vết brute-force, tài khoản lạ, backdoor, xoá log từ log Windows/Linux (local + SSH).",
        Category: "Ứng cứu sự cố",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: true,
        DisplayOrder: 70);

    public async Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;

        // If the user hasn't configured a forensics job, skip silently.
        if (!context.TryGetOption(OptionKey, out var payload) || string.IsNullOrWhiteSpace(payload))
        {
            _log.LogInformation("LogForensics: no settings present, skipping (module is user-interactive).");
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = Array.Empty<object>()
            };
        }

        ForensicsSettings settings;
        try
        {
            settings = JsonSerializer.Deserialize<ForensicsSettings>(payload)
                ?? throw new InvalidOperationException("Deserialized settings is null.");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "LogForensics: failed to deserialize settings payload.");
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = "Cấu hình forensics không hợp lệ: " + ex.Message,
                Findings = Array.Empty<object>()
            };
        }

        var fwd = new Progress<ForensicsProgress>(p =>
        {
            progress.Report(new ProgressUpdate(
                Metadata.Id,
                p.Message,
                PercentComplete: Math.Min(99, (int)Math.Min(99, p.FilesProcessed * 3 + p.RecordsProcessed / 10000)),
                Message: $"files={p.FilesProcessed}, records={p.RecordsProcessed}"));
        });

        try
        {
            var result = await _engine.RunAsync(settings, fwd, cancellationToken).ConfigureAwait(false);
            progress.Report(new ProgressUpdate(Metadata.Id, "Xong", 100,
                $"{result.TotalFiles} tệp, {result.TotalRecords} bản ghi, {result.Findings.Count} phát hiện"));

            // Store the full ForensicsResult in shared state so UI/report can enumerate manifest.
            context.SetShared("log-forensics.result", result);

            var findings = new List<object>(result.Findings.Count);
            foreach (var f in result.Findings) { findings.Add(f); }

            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            };
        }
        catch (OperationCanceledException)
        {
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = "Đã huỷ bởi người dùng.",
                Findings = Array.Empty<object>()
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "LogForensics run failed");
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = ex.Message,
                Findings = Array.Empty<object>()
            };
        }
    }
}
