using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using SysProcess = System.Diagnostics.Process;

namespace SecAudit.Infrastructure.Process;

[SupportedOSPlatform("windows")]
public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        using var proc = new SysProcess
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            },
            EnableRaisingEvents = true
        };

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                stdout.AppendLine(e.Data);
            }
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                stderr.AppendLine(e.Data);
            }
        };

        if (!proc.Start())
        {
            throw new InvalidOperationException($"Failed to start process: {fileName}");
        }
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout.HasValue)
        {
            cts.CancelAfter(timeout.Value);
        }

        try
        {
            await proc.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
            throw;
        }

        return new ProcessResult(proc.ExitCode, stdout.ToString(), stderr.ToString());
    }
}
