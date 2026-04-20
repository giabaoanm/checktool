using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Sources;

/// <summary>
/// Pulls log files from a remote host via SFTP (single or recursive) using SSH.NET.
/// Files are streamed to <c>%LOCALAPPDATA%\SecAudit\forensics\&lt;session&gt;\remote\</c>,
/// hashed with SHA-256 for chain-of-custody, and returned as <see cref="RawLogFile"/>.
/// Credentials (password / private key) live only for the duration of <c>EnumerateAsync</c>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SshLogSource : ILogSource
{
    private static readonly string[] LogExtensions =
        { ".log", ".txt", ".out", ".syslog", ".access", ".error", ".history" };

    private readonly ILogger<SshLogSource> _log;

    public SshLogSource(ILogger<SshLogSource> log) { _log = log; }

    public async IAsyncEnumerable<RawLogFile> EnumerateAsync(
        ForensicsSettings settings,
        IProgress<string> progress,
        [EnumeratorCancellation] CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(settings.SshHost))
        {
            progress.Report("SSH: host chưa cấu hình");
            yield break;
        }

        var localRoot = Path.Combine(settings.EvidenceRoot, "remote");
        Directory.CreateDirectory(localRoot);

        ConnectionInfo conn;
        if (!string.IsNullOrWhiteSpace(settings.SshPrivateKeyPath) && File.Exists(settings.SshPrivateKeyPath))
        {
            var pk = string.IsNullOrEmpty(settings.SshPrivateKeyPassphrase)
                ? new PrivateKeyFile(settings.SshPrivateKeyPath)
                : new PrivateKeyFile(settings.SshPrivateKeyPath, settings.SshPrivateKeyPassphrase);
            conn = new ConnectionInfo(settings.SshHost, settings.SshPort, settings.SshUsername,
                new PrivateKeyAuthenticationMethod(settings.SshUsername, pk));
        }
        else
        {
            conn = new ConnectionInfo(settings.SshHost, settings.SshPort, settings.SshUsername,
                new PasswordAuthenticationMethod(settings.SshUsername, settings.SshPassword ?? string.Empty));
        }

        using var sftp = new SftpClient(conn);
        progress.Report($"SSH: đang kết nối tới {settings.SshHost}:{settings.SshPort}...");
        try { sftp.Connect(); }
        catch (Exception ex)
        {
            _log.LogError(ex, "SSH connect failed");
            progress.Report($"SSH: lỗi kết nối — {ex.Message}");
            yield break;
        }

        var files = new List<ISftpFile>();
        try
        {
            CollectFiles(sftp, settings.SshRemotePath, settings.SshRecursive, files, settings.SshMaxFileBytes);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "SFTP listing failed");
            progress.Report($"SFTP: không liệt kê được đường dẫn — {ex.Message}");
            sftp.Disconnect();
            yield break;
        }

        foreach (var entry in files)
        {
            ct.ThrowIfCancellationRequested();

            var safeName = Sanitize(entry.FullName);
            var localPath = Path.Combine(localRoot, safeName);
            Directory.CreateDirectory(Path.GetDirectoryName(localPath)!);

            progress.Report($"SFTP: tải {entry.FullName} ({entry.Length} bytes)");
            try
            {
                await using var outFs = File.Create(localPath);
                sftp.DownloadFile(entry.FullName, outFs);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "SFTP download failed for {Path}", entry.FullName);
                progress.Report($"SFTP: bỏ qua {entry.FullName} — {ex.Message}");
                continue;
            }

            string sha;
            await using (var hs = File.OpenRead(localPath))
            {
                sha = Convert.ToHexString(await SHA256.HashDataAsync(hs, ct).ConfigureAwait(false));
            }

            yield return new RawLogFile(
                LocalPath: localPath,
                OriginalPath: $"sftp://{settings.SshUsername}@{settings.SshHost}{entry.FullName}",
                OsHint: "linux",
                SizeBytes: entry.Length,
                Sha256: sha);
        }

        sftp.Disconnect();
    }

    private static void CollectFiles(SftpClient sftp, string remotePath, bool recursive,
        List<ISftpFile> sink, int maxBytesPerFile)
    {
        foreach (var f in sftp.ListDirectory(remotePath))
        {
            if (f.Name is "." or "..") { continue; }
            if (f.IsDirectory)
            {
                if (recursive) { CollectFiles(sftp, f.FullName, recursive, sink, maxBytesPerFile); }
                continue;
            }
            if (!f.IsRegularFile) { continue; }
            if (f.Length > maxBytesPerFile) { continue; }
            var ext = Path.GetExtension(f.Name);
            var isLogByExt = Array.Exists(LogExtensions, e => string.Equals(e, ext, StringComparison.OrdinalIgnoreCase));
            var isAuth = f.Name.Equals("auth.log", StringComparison.OrdinalIgnoreCase)
                || f.Name.Equals("secure", StringComparison.OrdinalIgnoreCase)
                || f.Name.Equals("syslog", StringComparison.OrdinalIgnoreCase)
                || f.Name.Equals("messages", StringComparison.OrdinalIgnoreCase)
                || f.Name.StartsWith("auth.log.", StringComparison.OrdinalIgnoreCase);
            if (!isLogByExt && !isAuth) { continue; }
            sink.Add(f);
        }
    }

    private static string Sanitize(string remotePath)
    {
        var trimmed = remotePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
        foreach (var c in Path.GetInvalidFileNameChars())
        {
            trimmed = trimmed.Replace(c, '_');
        }
        return trimmed;
    }
}
