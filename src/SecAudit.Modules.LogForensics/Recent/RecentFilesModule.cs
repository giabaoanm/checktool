using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics.Recent;

/// <summary>
/// Auto-discovers Windows user profiles and analyses each user's Recent folder
/// (LNK shortcuts + JumpList summary) for forensic evidence of which files
/// were opened recently and from where (USB / Internet / suspicious paths).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RecentFilesModule : IAuditModule
{
    public const string OptionKeyUsersRoot = "recent-files.users-root";

    private readonly RecentFilesAnalyzer _analyzer;
    private readonly ILogger<RecentFilesModule> _logger;

    public RecentFilesModule(RecentFilesAnalyzer analyzer, ILogger<RecentFilesModule> logger)
    {
        _analyzer = analyzer;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "recent-files",
        DisplayName: "Recent files & JumpList artifacts",
        Description: "Phân tích .lnk shortcuts trong Recent + JumpList của Windows user — "
                     + "truy nguồn file đã mở gần đây (USB / Internet / phishing).",
        Category: "Ứng cứu sự cố",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: true,
        DisplayOrder: 71);

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
                    id: "RCT-NO-USERS-ROOT",
                    title: "Không xác định được thư mục Users để phân tích Recent files",
                    severity: Severity.Low,
                    category: "recent-files",
                    asset: context.MachineName,
                    evidence: $"Path đã thử: {usersRoot ?? "(rỗng)"}",
                    remediation: $"Set ScanContext.Options[\"{OptionKeyUsersRoot}\"] sang folder Users hợp lệ.")
            }, null));
        }

        progress.Report(new ProgressUpdate(Metadata.Id,
            "Đang quét Recent folder + JumpList...", 10));

        try
        {
            var result = _analyzer.Analyze(usersRoot, context.MachineName, cancellationToken);
            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Hoàn tất — {result.UsersExamined} user, {result.LnkFilesParsed} LNK, "
                + $"{result.JumpListFilesFound} JumpList, {result.Findings.Count} finding.", 100));

            var findings = result.Findings.Cast<object>().ToList();
            if (result.LnkFilesParsed == 0 && result.JumpListFilesFound == 0)
            {
                findings.Add(Finding.Create(
                    id: "RCT-EMPTY-SCAN",
                    title: "Không tìm thấy Recent / JumpList artifacts",
                    severity: Severity.Info,
                    category: "recent-files",
                    asset: context.MachineName,
                    evidence: $"Đã quét: {usersRoot}\nKhông có LNK trong Recent folder nào.",
                    remediation: "Có thể máy mới hoặc đã clear Recent qua GPO/manual."));
            }
            return Task.FromResult(Done(started, findings, null));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Recent files scan failed");
            return Task.FromResult(Done(started, new[]
            {
                Finding.Create(
                    id: "RCT-ANALYSIS-FAILED",
                    title: "Lỗi khi phân tích Recent files",
                    severity: Severity.Medium,
                    category: "recent-files",
                    asset: context.MachineName,
                    evidence: ex.Message,
                    remediation: "Kiểm tra log SecAudit; chạy với quyền admin để đọc Recent của user khác.")
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
