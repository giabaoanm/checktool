using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.LogForensics.Browser;

/// <summary>
/// Auto-runs browser forensics on every Windows user profile under <c>C:\Users</c>
/// (or another <c>C:\Users</c>-shaped folder pointed at via the option key).
/// Adds a sanity finding when no browser profile is discovered so the operator
/// knows the module ran but found nothing.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BrowserForensicsModule : IAuditModule
{
    /// <summary>Override the auto-discovered Users root (defaults to <c>%SystemDrive%\Users</c>).</summary>
    public const string OptionKeyUsersRoot = "browser-forensics.users-root";

    private readonly BrowserForensicsAnalyzer _analyzer;
    private readonly ILogger<BrowserForensicsModule> _logger;

    public BrowserForensicsModule(BrowserForensicsAnalyzer analyzer, ILogger<BrowserForensicsModule> logger)
    {
        _analyzer = analyzer;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "browser-forensics",
        DisplayName: "Browser Forensics (Chrome/Edge/Firefox)",
        Description: "Phân tích lịch sử trình duyệt + downloads + Mark-of-the-Web "
                     + "để truy nguồn gốc file độc trên máy người dùng (gắn link với hành vi phishing/drive-by).",
        Category: "Ứng cứu sự cố",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: true,
        DisplayOrder: 68);

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
                    id: "BRW-NO-USERS-ROOT",
                    title: "Không xác định được thư mục Users để phân tích trình duyệt",
                    severity: Severity.Low,
                    category: "browser-forensics",
                    asset: context.MachineName,
                    evidence: $"Path đã thử: {usersRoot ?? "(rỗng)"}",
                    remediation: "Chạy với quyền admin trên máy đích, hoặc set "
                               + $"ScanContext.Options[\"{OptionKeyUsersRoot}\"] sang folder Users hợp lệ.")
            }, null));
        }

        progress.Report(new ProgressUpdate(Metadata.Id,
            $"Đang quét lịch sử trình duyệt dưới {usersRoot}...", 10));

        try
        {
            var result = _analyzer.AnalyzeHost(usersRoot, context.MachineName, cancellationToken);
            progress.Report(new ProgressUpdate(Metadata.Id,
                $"Hoàn tất — {result.ProfilesScanned} profile, {result.VisitsExamined:N0} visit, "
                + $"{result.DownloadsExamined:N0} download, {result.Findings.Count} finding.", 100));

            var findings = result.Findings.Cast<object>().ToList();
            if (result.ProfilesScanned == 0)
            {
                findings.Add(Finding.Create(
                    id: "BRW-NO-PROFILE",
                    title: "Không tìm thấy profile trình duyệt nào",
                    severity: Severity.Low,
                    category: "browser-forensics",
                    asset: context.MachineName,
                    evidence: $"Đã quét: {usersRoot}\n"
                            + "Không có Chrome/Edge/Brave/Opera/CocCoc/Vivaldi/Firefox profile nào.",
                    remediation: "Có thể máy này không có user thực, hoặc browser cài ở đường dẫn "
                               + "ngoài chuẩn. Kiểm tra %APPDATA% / %LOCALAPPDATA%."));
            }

            return Task.FromResult(Done(started, findings, null));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Browser forensics failed");
            return Task.FromResult(Done(started, new[]
            {
                Finding.Create(
                    id: "BRW-ANALYSIS-FAILED",
                    title: "Lỗi khi phân tích trình duyệt",
                    severity: Severity.Medium,
                    category: "browser-forensics",
                    asset: context.MachineName,
                    evidence: ex.Message,
                    remediation: "Kiểm tra log SecAudit; đảm bảo native SQLite e_sqlite3 nạp được.")
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
