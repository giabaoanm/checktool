using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Detects an OCI image bundle on disk (a folder containing <c>oci-layout</c> +
/// <c>index.json</c> + <c>blobs/sha256/&lt;hash&gt;</c> blobs) and extracts the
/// flattened rootfs into a temp working directory so downstream parsers can scan
/// it as a regular Linux filesystem tree.
///
/// <para>This solves the silent-failure case where a user feeds the raw OCI bundle
/// to LogForensics and gets <c>0 files / 0 findings</c> because the scanner only
/// sees opaque <c>blobs/sha256/&lt;hash&gt;</c> binaries. After extraction the
/// usual <c>/var/log/auth.log</c>, <c>/etc/sudoers.d/*</c>, <c>/var/spool/cron</c>
/// artifacts become visible.</para>
///
/// <para>Limitations: handles single-layer images and multi-layer images via
/// in-order overlay (later layers overwrite earlier files; whiteout files
/// <c>.wh.*</c> remove paths). No xattr / device-node fidelity — this is for
/// read-only forensic inspection, not container restoration.</para>
/// </summary>
public sealed class OciImageExtractor
{
    public sealed record ExtractionResult(
        string RootfsPath,
        IReadOnlyList<string> ExtractedLayerDigests,
        long TotalBytes);

    public static bool LooksLikeOciBundle(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return false;
        }
        return File.Exists(Path.Combine(path, "oci-layout"))
            && File.Exists(Path.Combine(path, "index.json"))
            && Directory.Exists(Path.Combine(path, "blobs", "sha256"));
    }

    /// <summary>
    /// Extracts every layer referenced by the first manifest in <c>index.json</c>
    /// into <paramref name="targetRoot"/>. Returns the final rootfs path (same as
    /// targetRoot when extraction succeeds).
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance", "CA1822:Mark members as static",
        Justification = "Registered as DI singleton; instance-method API matches sibling extractors.")]
    public ExtractionResult Extract(string ociBundlePath, string targetRoot, CancellationToken ct)
    {
        if (!LooksLikeOciBundle(ociBundlePath))
        {
            throw new InvalidOperationException(
                "Path does not look like an OCI image bundle: " + ociBundlePath);
        }
        Directory.CreateDirectory(targetRoot);

        var indexJson = File.ReadAllText(Path.Combine(ociBundlePath, "index.json"));
        var index = JsonSerializer.Deserialize<JsonElement>(indexJson);
        var manifestDigest = index.GetProperty("manifests")[0]
            .GetProperty("digest").GetString()
            ?? throw new InvalidOperationException("index.json missing first manifest digest");

        var manifestPath = ResolveBlob(ociBundlePath, manifestDigest);
        var manifestJson = File.ReadAllText(manifestPath);
        var manifest = JsonSerializer.Deserialize<JsonElement>(manifestJson);

        var layerDigests = new List<string>();
        long totalBytes = 0;
        if (manifest.TryGetProperty("layers", out var layers))
        {
            foreach (var layer in layers.EnumerateArray())
            {
                ct.ThrowIfCancellationRequested();
                var digest = layer.GetProperty("digest").GetString()!;
                var blobPath = ResolveBlob(ociBundlePath, digest);
                ExtractLayer(blobPath, targetRoot, ct);
                layerDigests.Add(digest);
                totalBytes += new FileInfo(blobPath).Length;
            }
        }
        return new ExtractionResult(targetRoot, layerDigests, totalBytes);
    }

    private static string ResolveBlob(string ociBundlePath, string digest)
    {
        // digest format: "sha256:<hex>"
        var colon = digest.IndexOf(':', StringComparison.Ordinal);
        var algo = colon > 0 ? digest[..colon] : "sha256";
        var hex = colon > 0 ? digest[(colon + 1)..] : digest;
        var blob = Path.Combine(ociBundlePath, "blobs", algo, hex);
        if (!File.Exists(blob))
        {
            throw new FileNotFoundException("Missing blob: " + blob);
        }
        return blob;
    }

    /// <summary>
    /// Extracts a tar.gz layer over <paramref name="targetRoot"/>, applying OCI
    /// whiteout semantics: an entry named <c>.wh.foo</c> removes <c>foo</c> from
    /// the target; <c>.wh..wh..opq</c> opaque-dir markers are ignored (we don't
    /// support full overlayfs semantics — forensic scans don't need them).
    /// </summary>
    private static void ExtractLayer(string blobPath, string targetRoot, CancellationToken ct)
    {
        using var fileStream = File.OpenRead(blobPath);
        using var gz = new GZipStream(fileStream, CompressionMode.Decompress);
        using var reader = new TarReader(gz, leaveOpen: false);

        var rootFull = Path.GetFullPath(targetRoot);
        while (reader.GetNextEntry() is { } entry)
        {
            ct.ThrowIfCancellationRequested();
            var name = entry.Name.Replace('\\', '/');
            if (string.IsNullOrEmpty(name) || name.Contains("..", StringComparison.Ordinal))
            {
                continue;
            }
            var fileName = Path.GetFileName(name);
            if (fileName.StartsWith(".wh.", StringComparison.Ordinal))
            {
                if (fileName == ".wh..wh..opq")
                {
                    continue;
                }
                var dir = Path.GetDirectoryName(name) ?? string.Empty;
                var realName = fileName[".wh.".Length..];
                var victim = Path.Combine(rootFull, dir.Replace('/', Path.DirectorySeparatorChar), realName);
                TryRemove(victim);
                continue;
            }

            var dest = Path.Combine(rootFull, name.Replace('/', Path.DirectorySeparatorChar));
            // Defence in depth — refuse paths that escape rootfs.
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
                    if (!string.IsNullOrEmpty(parent))
                    {
                        Directory.CreateDirectory(parent);
                    }
                    using var output = File.Create(dest);
                    entry.DataStream?.CopyTo(output);
                }
                // Symlinks / char-devices / block-devices are skipped; not
                // meaningful for read-only forensic content scan.
            }
            catch (IOException) { /* skip locked / too-long / unsupported entries */ }
            catch (UnauthorizedAccessException) { /* skip */ }
        }
    }

    private static void TryRemove(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
            else if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // best effort
        }
    }
}
