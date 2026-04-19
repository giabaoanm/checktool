using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.Hardening.Checks;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.Hardening;

/// <summary>
/// Iteration 2 module. Runs all <see cref="ICheck"/> instances in parallel and aggregates
/// their findings. Each check is independent and reads-only.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HardeningModule : IAuditModule
{
    private readonly IEnumerable<ICheck> _checks;
    private readonly ILogger<HardeningModule> _logger;

    public HardeningModule(IEnumerable<ICheck> checks, ILogger<HardeningModule> logger)
    {
        _checks = checks;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "hardening",
        DisplayName: "Hardening (CIS-style)",
        Description: "Read-only CIS-style configuration checks: UAC, SMBv1, RDP-NLA, Defender, Firewall, BitLocker, etc.",
        Category: "Configuration",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: false,
        DisplayOrder: 20);

    public async Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var checkList = _checks.ToList();
        var findings = new List<object>();

        if (checkList.Count == 0)
        {
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            };
        }

        var ctx = new CheckContext { Asset = context.MachineName };
        progress.Report(new ProgressUpdate(Metadata.Id, $"Running {checkList.Count} checks", 5));

        var completed = 0;
        var lockObj = new object();

        var tasks = checkList.Select(async check =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var finding = await check.RunAsync(ctx, cancellationToken).ConfigureAwait(false);
                if (finding is not null)
                {
                    lock (lockObj)
                    {
                        findings.Add(finding);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Check {CheckId} threw", check.Metadata.Id);
            }
            finally
            {
                var done = Interlocked.Increment(ref completed);
                var pct = 5 + (int)(90.0 * done / checkList.Count);
                progress.Report(new ProgressUpdate(Metadata.Id, check.Metadata.Id, pct));
            }
        }).ToArray();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = "Cancelled",
                Findings = findings
            };
        }

        progress.Report(new ProgressUpdate(Metadata.Id, "Done", 100));

        return new ModuleResult
        {
            ModuleId = Metadata.Id,
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            Succeeded = true,
            Findings = findings
        };
    }
}
