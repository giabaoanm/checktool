using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics.Office;

/// <summary>
/// Auto-runs Office &amp; Outlook artifact analysis on the host. Mirrors
/// <see cref="Browser.BrowserForensicsModule"/>: discovers
/// <c>%SystemDrive%\Users\</c>, queries HKCU Trusted Documents, walks Downloads /
/// Documents / Temp / Outlook attachment cache. Emits findings tagged with
/// MITRE T1566.001 + T1204.002 so SOC can pivot from <q>file on disk</q> to
/// <q>email/attachment that delivered it</q>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OfficeArtifactsModule : IAuditModule
{
    public const string OptionKeyUsersRoot = "office-artifacts.users-root";

    private readonly OfficeArtifactsAnalyzer _analyzer;
    private readonly ILogger<OfficeArtifactsModule> _logger;

    public OfficeArtifactsModule(OfficeArtifactsAnalyzer analyzer, ILogger<OfficeArtifactsModule> logger)
    {
        _analyzer = analyzer;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "office-artifacts",
        DisplayName: "Office & Outlook Artifacts",
        Description: "Phát hiện file Office macro được user enable, attachment Outlook đã mở, "
                     + "và file .docm/.xlsm/.pptm trong Downloads/Temp — truy nguồn email phishing.",
        Category: "Ứng cứu sự cố",
        Version: "1.0.0",
        RequiresAdministrator: false,
        IsSensitive: true,
        DisplayOrder: 69);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(progress);
        var started = DateTimeOffset.UtcNow;

        var usersRoot = ResolveUsersRoot(context);
        if (string.IsNullOrWhiteSpace(usersRoot) || !Directory.Exists(usersRoot))
        {
            return Task.FromResult(Done(started, new[]
            {
                Finding.Create(
                    id: "OFC-NO-USERS-ROOT",
                    title: "Không xác định được thư mục Users để phân tích Office artifacts",
                    severity: Severity.Low,
                    category: "office-artifacts",
                    asset: context.MachineName,
                    evidence: $"Path đã thử: {usersRoot ?? "(rỗng)"}",
                    remediation: $"Set ScanContext.Options[\"{OptionKeyUsersRoot}\"] sang folder Users hợp lệ.")
            }, null));
        }

        progress.Report(new ProgressUpdate(Metadata.Id,
            "Đang quét Office Trusted Documents + Outlook cache...", 10));

        try
        {
            var result = _analyzer.Analyze(usersRoot, context.MachineName, cancellationToken);
            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Hoàn tất — {result.TrustedDocsScanned} trust record, "
                + $"{result.MacroFilesScanned} macro file, {result.OutlookCacheFilesScanned} attachment cache, "
                + $"{result.Findings.Count} finding.", 100));

            var findings = result.Findings.Cast<object>().ToList();
            if (result.TrustedDocsScanned == 0 && result.MacroFilesScanned == 0
                && result.OutlookCacheFilesScanned == 0)
            {
                findings.Add(Finding.Create(
                    id: "OFC-EMPTY-SCAN",
                    title: "Không tìm thấy artifact Office/Outlook",
                    severity: Severity.Info,
                    category: "office-artifacts",
                    asset: context.MachineName,
                    evidence: $"Đã quét: {usersRoot}\n"
                            + "Không có TrustRecord, file .docm/.xlsm trong Downloads/Documents, "
                            + "hay file trong Outlook cache.",
                    remediation: "Có thể máy này chưa cài Office hoặc user chưa từng mở "
                               + "tệp đính kèm Outlook. Không phải false-positive."));
            }

            return Task.FromResult(Done(started, findings, null));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Office artifacts scan failed");
            return Task.FromResult(Done(started, new[]
            {
                Finding.Create(
                    id: "OFC-ANALYSIS-FAILED",
                    title: "Lỗi khi phân tích Office artifacts",
                    severity: Severity.Medium,
                    category: "office-artifacts",
                    asset: context.MachineName,
                    evidence: ex.Message,
                    remediation: "Kiểm tra log SecAudit; chạy với quyền admin để đọc HKCU của user khác.")
            }, ex.Message, succeeded: false));
        }
    }

    private static string? ResolveUsersRoot(ScanContext context)
    {
        if (context.TryGetOption(OptionKeyUsersRoot, out var explicitPath)
            && !string.IsNullOrWhiteSpace(explicitPath))
        {
            return explicitPath;
        }
        var systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        return Path.Combine(systemDrive + "\\", "Users");
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
