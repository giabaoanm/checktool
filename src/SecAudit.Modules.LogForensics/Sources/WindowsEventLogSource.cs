using System.Diagnostics.Eventing.Reader;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Sources;

/// <summary>
/// Exports a live Windows Event Log channel (Security/System/Sysmon/PowerShell) to a
/// temporary *.evtx snapshot, then yields it as a <see cref="RawLogFile"/> so the
/// EVTX parser handles it uniformly with offline files.
///
/// Rationale: we never read from the live channel directly — a snapshot gives us a
/// stable file we can hash and archive for chain-of-custody.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogSource : ILogSource
{
    public async IAsyncEnumerable<RawLogFile> EnumerateAsync(
        ForensicsSettings settings,
        IProgress<string> progress,
        [EnumeratorCancellation] CancellationToken ct)
    {
        // If caller provided an existing EVTX file, treat it like LocalFolderSource.
        if (!string.IsNullOrWhiteSpace(settings.EvtxFile) && File.Exists(settings.EvtxFile!))
        {
            var path = settings.EvtxFile!;
            var hash = await Sha256Async(path, ct).ConfigureAwait(false);
            progress.Report($"using provided EVTX: {Path.GetFileName(path)}");
            yield return new RawLogFile(path, path, "windows", new FileInfo(path).Length, hash);
            yield break;
        }

        // Otherwise snapshot the live channel into evidence folder.
        var channel = string.IsNullOrWhiteSpace(settings.EventLogChannel) ? "Security" : settings.EventLogChannel;
        Directory.CreateDirectory(settings.EvidenceRoot);
        var safeName = channel.Replace("/", "_").Replace("\\", "_").Replace(" ", "_");
        var snapshotPath = Path.Combine(settings.EvidenceRoot, $"{safeName}.evtx");

        progress.Report($"exporting channel {channel} to snapshot...");
        try
        {
            var session = new EventLogSession();
            session.ExportLogAndMessages(channel, PathType.LogName, "*", snapshotPath);
        }
        catch (UnauthorizedAccessException ex)
        {
            progress.Report($"EVTX export denied ({ex.Message}) — ensure running as admin");
            yield break;
        }
        catch (EventLogException ex)
        {
            progress.Report($"EVTX export failed: {ex.Message}");
            yield break;
        }

        var outHash = await Sha256Async(snapshotPath, ct).ConfigureAwait(false);
        yield return new RawLogFile(
            LocalPath: snapshotPath,
            OriginalPath: $"EventLog://{channel}",
            OsHint: "windows",
            SizeBytes: new FileInfo(snapshotPath).Length,
            Sha256: outHash);
    }

    private static async Task<string> Sha256Async(string path, CancellationToken ct)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(fs, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }
}
