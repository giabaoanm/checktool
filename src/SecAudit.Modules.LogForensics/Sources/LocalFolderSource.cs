using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Sources;

/// <summary>
/// Enumerates log files from a user-picked folder (or single file). Hashes each file
/// up-front so chain-of-custody is preserved even if the file is modified during scan.
/// </summary>
public sealed class LocalFolderSource : ILogSource
{
    private static readonly string[] KnownExtensions =
    {
        ".evtx", ".log", ".txt", ".out", ".syslog", ".access", ".error", ".history", ".csv",
        // .xml for wevtutil/PowerShell-exported Windows Event Logs. WindowsEventXmlParser
        // further filters by filename (sysmon/security/winevt/… substrings) so random
        // application config XML in the same folder is still ignored.
        ".xml"
    };

    public async IAsyncEnumerable<RawLogFile> EnumerateAsync(
        ForensicsSettings settings,
        IProgress<string> progress,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var root = settings.LocalPath;
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root) && !File.Exists(root))
        {
            yield break;
        }

        IEnumerable<string> paths;
        if (File.Exists(root))
        {
            paths = new[] { root };
        }
        else
        {
            var opts = new EnumerationOptions
            {
                RecurseSubdirectories = settings.LocalRecursive,
                IgnoreInaccessible = true,
                MatchType = MatchType.Simple
            };
            paths = Directory.EnumerateFiles(root, "*", opts);
        }

        int count = 0;
        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(p).ToLowerInvariant();
            var actualPath = p;
            var isGzippedLog = ext == ".gz" && LooksLikeRotatedLog(p);

            if (isGzippedLog)
            {
                // Transparent gzip: decompress to a sibling temp file so the existing
                // parsers (which expect plain-text streams) can ingest auth.log.3.gz,
                // syslog.1.gz, audit.log.1.gz exactly the same as the un-rotated file.
                try
                {
                    actualPath = await DecompressGzipAsync(p, ct).ConfigureAwait(false);
                    ext = Path.GetExtension(actualPath).ToLowerInvariant();
                }
                catch (Exception ex)
                {
                    progress.Report($"skip (gunzip failed): {p} — {ex.Message}");
                    continue;
                }
            }
            else if (!KnownExtensions.Contains(ext) && !IsLikelyBashHistory(p))
            {
                continue;
            }

            FileInfo fi;
            try { fi = new FileInfo(actualPath); }
            catch { continue; }

            string hash;
            try
            {
                // Hash the ORIGINAL file (not the decompressed copy) so chain-of-custody
                // pins to what the operator collected from disk.
                hash = await Sha256Async(p, ct).ConfigureAwait(false);
            }
            catch
            {
                progress.Report($"skip (unreadable): {p}");
                continue;
            }

            count++;
            progress.Report($"enumerated {count}: {Path.GetFileName(p)}"
                + (isGzippedLog ? " (gunzipped)" : ""));
            yield return new RawLogFile(
                LocalPath: actualPath,
                OriginalPath: p,
                OsHint: ext == ".evtx" ? "windows" : GuessOs(p),
                SizeBytes: fi.Length,
                Sha256: hash);
        }
    }

    private static bool LooksLikeRotatedLog(string path)
    {
        // Strip .gz then check the resulting filename matches a rotated-log pattern
        // (name typically ends in .log.<digit> or .<digit>.log or .log when re-rotated).
        var stem = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        if (stem.EndsWith(".log", StringComparison.Ordinal)) { return true; }
        if (stem.Contains(".log.", StringComparison.Ordinal)) { return true; }
        // common patterns: auth.log.1, syslog.2, audit.log.1, kern.log.3, messages.0
        var name = Path.GetFileNameWithoutExtension(stem);
        return name is "syslog" or "messages" or "kern" or "auth"
            || stem.StartsWith("auth.", StringComparison.Ordinal)
            || stem.StartsWith("audit.", StringComparison.Ordinal)
            || stem.StartsWith("syslog.", StringComparison.Ordinal)
            || stem.StartsWith("nginx.", StringComparison.Ordinal)
            || stem.StartsWith("apache.", StringComparison.Ordinal)
            || stem.StartsWith("access.", StringComparison.Ordinal)
            || stem.StartsWith("error.", StringComparison.Ordinal);
    }

    private static async Task<string> DecompressGzipAsync(string gzPath, CancellationToken ct)
    {
        // Sibling temp file preserves chain-of-custody (original .gz file untouched)
        // while letting existing parsers read plain text.
        var tempDir = Path.Combine(Path.GetTempPath(), "secaudit-gunzip");
        Directory.CreateDirectory(tempDir);
        var stem = Path.GetFileNameWithoutExtension(gzPath);
        var outPath = Path.Combine(tempDir,
            stem + "-" + Path.GetFileNameWithoutExtension(Path.GetTempFileName()) + ".log");

        await using var input = File.OpenRead(gzPath);
        await using var gz = new GZipStream(input, CompressionMode.Decompress);
        await using var output = File.Create(outPath);
        await gz.CopyToAsync(output, ct).ConfigureAwait(false);
        return outPath;
    }

    private static bool IsLikelyBashHistory(string path)
        => string.Equals(Path.GetFileName(path), ".bash_history", StringComparison.OrdinalIgnoreCase)
           || string.Equals(Path.GetFileName(path), "bash_history", StringComparison.OrdinalIgnoreCase);

    private static string GuessOs(string path)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        if (name.Contains("auth") || name.Contains("secure") || name.Contains("syslog")
            || name.Contains("messages") || name.Contains("nginx") || name.Contains("apache")
            || name.EndsWith(".history") || name == ".bash_history")
        {
            return "linux";
        }
        return "unknown";
    }

    private static async Task<string> Sha256Async(string path, CancellationToken ct)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(fs, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }
}
