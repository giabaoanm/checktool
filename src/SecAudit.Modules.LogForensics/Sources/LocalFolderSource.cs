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
            if (!KnownExtensions.Contains(ext) && !IsLikelyBashHistory(p))
            {
                continue;
            }

            FileInfo fi;
            try { fi = new FileInfo(p); }
            catch { continue; }

            string hash;
            try
            {
                hash = await Sha256Async(p, ct).ConfigureAwait(false);
            }
            catch
            {
                progress.Report($"skip (unreadable): {p}");
                continue;
            }

            count++;
            progress.Report($"enumerated {count}: {Path.GetFileName(p)}");
            yield return new RawLogFile(
                LocalPath: p,
                OriginalPath: p,
                OsHint: ext == ".evtx" ? "windows" : GuessOs(p),
                SizeBytes: fi.Length,
                Sha256: hash);
        }
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
