using System.Formats.Tar;
using System.IO.Compression;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Detect-and-extract for the archive formats that an analyst typically receives
/// alongside a Linux IR ticket: <c>.tar</c>, <c>.tar.gz</c>/<c>.tgz</c>,
/// <c>.tar.bz2</c>/<c>.tbz2</c> (gzip + bzip2 streams), and <c>.zip</c>. Used
/// transparently before <see cref="LinuxIncidentAnalyzer"/> so the user can point
/// at <c>victim.tar.gz</c> directly without unpacking by hand first.
///
/// <para>Path-traversal protection is mandatory — every entry is normalised and
/// refused if it would write outside <c>targetRoot</c> (defence against the
/// classic Zip Slip / "evil tar" attack on forensic workstations).</para>
///
/// <para>Limitations: native <c>.7z</c> + <c>.xz</c> + <c>.rar</c> need
/// third-party libraries (SharpCompress) which we don't ship to keep the
/// portable .exe small. Document them as roadmap.</para>
/// </summary>
public static class ArchiveExtractor
{
    public enum ArchiveKind
    {
        None,
        Tar,
        TarGz,
        TarBz2,
        Zip
    }

    public static ArchiveKind Detect(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { return ArchiveKind.None; }
        var lower = path.ToLowerInvariant();
        if (lower.EndsWith(".tar.gz", StringComparison.Ordinal)
            || lower.EndsWith(".tgz", StringComparison.Ordinal))
        {
            return ArchiveKind.TarGz;
        }
        if (lower.EndsWith(".tar.bz2", StringComparison.Ordinal)
            || lower.EndsWith(".tbz2", StringComparison.Ordinal)
            || lower.EndsWith(".tbz", StringComparison.Ordinal))
        {
            return ArchiveKind.TarBz2;
        }
        if (lower.EndsWith(".tar", StringComparison.Ordinal)) { return ArchiveKind.Tar; }
        if (lower.EndsWith(".zip", StringComparison.Ordinal)) { return ArchiveKind.Zip; }
        // Fall back to magic-byte sniff for misnamed files.
        return SniffByMagic(path);
    }

    private static ArchiveKind SniffByMagic(string path)
    {
        try
        {
            byte[] head = new byte[8];
            using var fs = File.OpenRead(path);
            int n = fs.Read(head, 0, head.Length);
            if (n < 4) { return ArchiveKind.None; }

            // Gzip
            if (head[0] == 0x1F && head[1] == 0x8B) { return ArchiveKind.TarGz; }
            // Zip ("PK\x03\x04")
            if (head[0] == 0x50 && head[1] == 0x4B && head[2] == 0x03 && head[3] == 0x04)
            {
                return ArchiveKind.Zip;
            }
            // Bzip2 ("BZh")
            if (head[0] == 0x42 && head[1] == 0x5A && head[2] == 0x68) { return ArchiveKind.TarBz2; }
        }
        catch
        {
            // best effort
        }
        return ArchiveKind.None;
    }

    public static void Extract(string archivePath, string targetRoot, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetRoot);
        Directory.CreateDirectory(targetRoot);

        var kind = Detect(archivePath);
        switch (kind)
        {
            case ArchiveKind.Tar:
                ExtractTar(archivePath, targetRoot, ct);
                break;
            case ArchiveKind.TarGz:
                ExtractTarStream(archivePath, targetRoot, asGzip: true, asBzip2: false, ct);
                break;
            case ArchiveKind.TarBz2:
                ExtractTarStream(archivePath, targetRoot, asGzip: false, asBzip2: true, ct);
                break;
            case ArchiveKind.Zip:
                ExtractZip(archivePath, targetRoot, ct);
                break;
            default:
                throw new InvalidOperationException(
                    "Unsupported or unrecognised archive format: " + archivePath);
        }
    }

    private static void ExtractTar(string path, string root, CancellationToken ct)
    {
        using var fs = File.OpenRead(path);
        ExtractTarFromStream(fs, root, ct);
    }

    private static void ExtractTarStream(string path, string root, bool asGzip, bool asBzip2, CancellationToken ct)
    {
        using var fs = File.OpenRead(path);
        Stream inner = fs;
        if (asGzip) { inner = new GZipStream(fs, CompressionMode.Decompress, leaveOpen: false); }
        else if (asBzip2)
        {
            // .NET 8 has no built-in bzip2. Throw with a clear message so the GUI surfaces it.
            throw new NotSupportedException(
                "Định dạng .tar.bz2 chưa được hỗ trợ — vui lòng giải nén thủ công bằng "
                + "7-Zip / bzip2 trước, sau đó point lại vào folder đã giải nén.");
        }
        using (inner)
        {
            ExtractTarFromStream(inner, root, ct);
        }
    }

    private static void ExtractTarFromStream(Stream tar, string targetRoot, CancellationToken ct)
    {
        var rootFull = Path.GetFullPath(targetRoot);
        using var reader = new TarReader(tar, leaveOpen: true);
        while (reader.GetNextEntry() is { } entry)
        {
            ct.ThrowIfCancellationRequested();
            var name = entry.Name.Replace('\\', '/');
            if (string.IsNullOrEmpty(name) || name.Contains("..", StringComparison.Ordinal))
            {
                continue; // path traversal defence
            }
            var dest = Path.Combine(rootFull, name.Replace('/', Path.DirectorySeparatorChar));
            if (!Path.GetFullPath(dest).StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            try
            {
                if (entry.EntryType is TarEntryType.Directory)
                {
                    Directory.CreateDirectory(dest);
                }
                else if (entry.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile)
                {
                    var parent = Path.GetDirectoryName(dest);
                    if (!string.IsNullOrEmpty(parent)) { Directory.CreateDirectory(parent); }
                    using var output = File.Create(dest);
                    entry.DataStream?.CopyTo(output);
                }
            }
            catch (IOException) { /* skip locked / too-long */ }
            catch (UnauthorizedAccessException) { /* skip */ }
        }
    }

    private static void ExtractZip(string path, string targetRoot, CancellationToken ct)
    {
        var rootFull = Path.GetFullPath(targetRoot);
        using var zip = ZipFile.OpenRead(path);
        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var name = entry.FullName.Replace('\\', '/');
            if (string.IsNullOrEmpty(name) || name.Contains("..", StringComparison.Ordinal))
            {
                continue;
            }
            var dest = Path.Combine(rootFull, name.Replace('/', Path.DirectorySeparatorChar));
            if (!Path.GetFullPath(dest).StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            try
            {
                if (string.IsNullOrEmpty(entry.Name))
                {
                    Directory.CreateDirectory(dest);
                }
                else
                {
                    var parent = Path.GetDirectoryName(dest);
                    if (!string.IsNullOrEmpty(parent)) { Directory.CreateDirectory(parent); }
                    entry.ExtractToFile(dest, overwrite: true);
                }
            }
            catch (IOException) { /* skip */ }
            catch (UnauthorizedAccessException) { /* skip */ }
        }
    }
}
