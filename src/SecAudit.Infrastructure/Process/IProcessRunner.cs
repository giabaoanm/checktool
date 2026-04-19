namespace SecAudit.Infrastructure.Process;

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default);
}
