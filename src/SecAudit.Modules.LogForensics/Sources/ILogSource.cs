using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Sources;

/// <summary>
/// Produces raw <see cref="RawLogFile"/>s (already on local disk, ready to feed parsers).
/// SSH/SFTP source downloads files first; local folder source just enumerates; Windows
/// EventLog source enumerates channels and saves to *.evtx snapshots.
///
/// Separating source from parser lets us mix-and-match: e.g. SSH-pull an evtx from a
/// remote Windows server and feed it to WindowsEvtxParser.
/// </summary>
public interface ILogSource
{
    IAsyncEnumerable<RawLogFile> EnumerateAsync(
        ForensicsSettings settings,
        IProgress<string> progress,
        CancellationToken ct);
}

/// <summary>
/// One log file pulled from a source, ready to parse. Absolute path is always on the
/// local machine (copied from remote if needed). Hash supports chain-of-custody.
/// </summary>
public sealed record RawLogFile(
    string LocalPath,
    string OriginalPath,
    string OsHint,
    long SizeBytes,
    string Sha256);
