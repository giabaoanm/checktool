using Microsoft.Data.Sqlite;

namespace SecAudit.Modules.LogForensics.Browser;

/// <summary>
/// Reads Chromium-based (Chrome / Edge / Brave / Opera / Cốc Cốc) and Firefox
/// browser history databases. Both engines store history in SQLite — Chromium
/// in <c>History</c>, Firefox in <c>places.sqlite</c>.
///
/// <para>Browsers hold an exclusive lock on the live DB. We side-step it by copying
/// the file (and the WAL/SHM if present) to a temp directory before opening, so
/// we don't need to ask the user to close the browser first.</para>
///
/// <para>What we extract:</para>
/// <list type="bullet">
///   <item><b>Visits</b> — URL, title, last visit time, visit count.</item>
///   <item><b>Downloads</b> — target file path, source URL, MIME type, total bytes,
///         start/end time, danger type (Chromium SafeBrowsing verdict).</item>
/// </list>
/// </summary>
public static class BrowserHistoryReader
{
    public sealed record VisitRecord(
        string Url,
        string Title,
        DateTimeOffset? LastVisit,
        int VisitCount,
        string Browser);

    public sealed record DownloadRecord(
        string TargetPath,
        string SourceUrl,
        string MimeType,
        long TotalBytes,
        DateTimeOffset? StartTime,
        DateTimeOffset? EndTime,
        int DangerType,             // Chromium: 0=NotDangerous, 1=Dangerous, 2=DangerousFile, 4=DangerousUrl, 9=DangerousHost
        string TabReferrerUrl,
        string Browser);

    static BrowserHistoryReader()
    {
        // Force the e_sqlite3 native loader registration; required when the host
        // hasn't already touched a SQLitePCL API.
        SQLitePCL.Batteries_V2.Init();
    }

    /// <summary>Read Chromium History DB. Caller MUST handle file-not-found case upstream.</summary>
    public static (IReadOnlyList<VisitRecord> Visits, IReadOnlyList<DownloadRecord> Downloads)
        ReadChromium(string historyDbPath, string browserLabel, int maxRows = 5000)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(historyDbPath);
        if (!File.Exists(historyDbPath))
        {
            return (Array.Empty<VisitRecord>(), Array.Empty<DownloadRecord>());
        }

        var copied = CopyDbForRead(historyDbPath);
        try
        {
            var visits = new List<VisitRecord>();
            var downloads = new List<DownloadRecord>();
            using var conn = new SqliteConnection($"Data Source={copied};Mode=ReadOnly;Cache=Private");
            conn.Open();

            // Visits: urls table has visit_count + last_visit_time (microseconds since 1601-01-01 UTC)
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText =
                    "SELECT url, title, visit_count, last_visit_time " +
                    "FROM urls " +
                    "ORDER BY last_visit_time DESC " +
                    $"LIMIT {maxRows};";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    visits.Add(new VisitRecord(
                        Url: r.GetString(0),
                        Title: r.IsDBNull(1) ? string.Empty : r.GetString(1),
                        VisitCount: r.GetInt32(2),
                        LastVisit: WebkitMicroToDateTime(r.GetInt64(3)),
                        Browser: browserLabel));
                }
            }

            // Downloads: schema varies by Chromium version; the columns below are stable since 2017.
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText =
                    "SELECT target_path, current_path, mime_type, total_bytes, " +
                    "start_time, end_time, danger_type, tab_referrer_url, " +
                    "(SELECT url FROM downloads_url_chains uc WHERE uc.id = downloads.id ORDER BY chain_index DESC LIMIT 1) AS source_url " +
                    "FROM downloads " +
                    "ORDER BY start_time DESC " +
                    $"LIMIT {maxRows};";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var target = r.IsDBNull(0) ? string.Empty : r.GetString(0);
                    if (string.IsNullOrEmpty(target) && !r.IsDBNull(1)) { target = r.GetString(1); }
                    downloads.Add(new DownloadRecord(
                        TargetPath: target,
                        MimeType: r.IsDBNull(2) ? string.Empty : r.GetString(2),
                        TotalBytes: r.IsDBNull(3) ? 0 : r.GetInt64(3),
                        StartTime: r.IsDBNull(4) ? null : WebkitMicroToDateTime(r.GetInt64(4)),
                        EndTime: r.IsDBNull(5) ? null : WebkitMicroToDateTime(r.GetInt64(5)),
                        DangerType: r.IsDBNull(6) ? 0 : r.GetInt32(6),
                        TabReferrerUrl: r.IsDBNull(7) ? string.Empty : r.GetString(7),
                        SourceUrl: r.IsDBNull(8) ? string.Empty : r.GetString(8),
                        Browser: browserLabel));
                }
            }
            catch (SqliteException)
            {
                // Old schema or downloads table missing — skip silently.
            }

            return (visits, downloads);
        }
        finally
        {
            try { File.Delete(copied); } catch { /* best effort */ }
        }
    }

    /// <summary>Read Firefox places.sqlite (similar shape but different table names).</summary>
    public static (IReadOnlyList<VisitRecord> Visits, IReadOnlyList<DownloadRecord> Downloads)
        ReadFirefox(string placesDbPath, int maxRows = 5000)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(placesDbPath);
        if (!File.Exists(placesDbPath))
        {
            return (Array.Empty<VisitRecord>(), Array.Empty<DownloadRecord>());
        }

        var copied = CopyDbForRead(placesDbPath);
        try
        {
            var visits = new List<VisitRecord>();
            using var conn = new SqliteConnection($"Data Source={copied};Mode=ReadOnly;Cache=Private");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText =
                "SELECT url, title, visit_count, last_visit_date " +
                "FROM moz_places " +
                "WHERE last_visit_date IS NOT NULL " +
                "ORDER BY last_visit_date DESC " +
                $"LIMIT {maxRows};";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                visits.Add(new VisitRecord(
                    Url: r.GetString(0),
                    Title: r.IsDBNull(1) ? string.Empty : r.GetString(1),
                    VisitCount: r.IsDBNull(2) ? 0 : r.GetInt32(2),
                    LastVisit: r.IsDBNull(3) ? null : UnixMicroToDateTime(r.GetInt64(3)),
                    Browser: "Firefox"));
            }

            // Firefox download data lives in moz_annos with annotation 'downloads/destinationFileURI'
            // — we skip the older schema and recommend manual export from about:downloads
            // to keep this reader compact. v2 enhancement.
            return (visits, Array.Empty<DownloadRecord>());
        }
        finally
        {
            try { File.Delete(copied); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Copy the live DB (and WAL/SHM if present) to a temp file so we can open it
    /// even while the browser holds an exclusive lock. Read-only opens still need
    /// the file to be unlocked because SQLite reads journal headers.
    /// </summary>
    private static string CopyDbForRead(string dbPath)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "secaudit-browserdb");
        Directory.CreateDirectory(tempDir);
        var stem = Path.GetFileNameWithoutExtension(dbPath);
        var dest = Path.Combine(tempDir,
            stem + "-" + Guid.NewGuid().ToString("N")[..8] + Path.GetExtension(dbPath));

        File.Copy(dbPath, dest, overwrite: true);
        // WAL + SHM siblings must travel together or SQLite refuses to open.
        var wal = dbPath + "-wal";
        if (File.Exists(wal))
        {
            try { File.Copy(wal, dest + "-wal", overwrite: true); } catch { /* ignore */ }
        }
        var shm = dbPath + "-shm";
        if (File.Exists(shm))
        {
            try { File.Copy(shm, dest + "-shm", overwrite: true); } catch { /* ignore */ }
        }
        return dest;
    }

    // Chromium epoch: 1601-01-01 UTC, microseconds.
    private static DateTimeOffset? WebkitMicroToDateTime(long microseconds)
    {
        if (microseconds <= 0) { return null; }
        try
        {
            var ticks = microseconds * 10L;
            return new DateTimeOffset(new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks + ticks,
                TimeSpan.Zero);
        }
        catch { return null; }
    }

    // Firefox epoch: Unix microseconds.
    private static DateTimeOffset? UnixMicroToDateTime(long microseconds)
    {
        if (microseconds <= 0) { return null; }
        try { return DateTimeOffset.FromUnixTimeMilliseconds(microseconds / 1000); }
        catch { return null; }
    }
}
