using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hello;

/// <summary>
/// Smoke-test module: confirms DI registration, contract shape, and progress reporting end-to-end.
/// Will be removed once a real module exists in every category.
/// </summary>
public sealed class HelloModule : IAuditModule
{
    private readonly ILogger<HelloModule> _logger;

    public HelloModule(ILogger<HelloModule> logger)
    {
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "hello",
        DisplayName: "Hello (demo)",
        Description: "Pipeline smoke test. Produces a single Info finding.",
        Category: "Demo",
        Version: "0.1.0",
        RequiresAdministrator: false,
        IsSensitive: false,
        DisplayOrder: 999);

    public async Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(progress);

        var startedAt = DateTimeOffset.UtcNow;
        _logger.LogInformation("HelloModule started on {Machine}", context.MachineName);

        progress.Report(new ProgressUpdate(Metadata.Id, "init", 10, "Warming up"));
        await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        progress.Report(new ProgressUpdate(Metadata.Id, "scan", 60, "Pretending to scan"));
        await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        progress.Report(new ProgressUpdate(Metadata.Id, "done", 100, "Complete"));

        var finding = Finding.Create(
            id: "HELLO-001",
            title: "Pipeline plugin hoạt động bình thường",
            severity: Severity.Info,
            category: "Demo",
            asset: context.MachineName,
            evidence: $"Module {Metadata.Id} chạy lúc {startedAt:O}",
            remediation: "Không cần xử lý.");

        return new ModuleResult
        {
            ModuleId = Metadata.Id,
            StartedAt = startedAt,
            CompletedAt = DateTimeOffset.UtcNow,
            Succeeded = true,
            Findings = new object[] { finding }
        };
    }
}
