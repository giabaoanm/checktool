using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace SecAudit.Cve.Pipeline;

/// <summary>
/// Opens (or creates, from embedded <c>Schema.sql</c>) the local SQLite CVE database.
/// Path defaults to <c>%LOCALAPPDATA%\SecAudit\cve\cve.db</c>. The app only reads from this
/// DB in v1; an opt-in online sync job writes into it.
/// </summary>
public sealed class CveDatabase
{
    private const string SchemaResource = "SecAudit.Cve.Pipeline.Schema.sql";
    private readonly ILogger<CveDatabase> _logger;

    public CveDatabase(ILogger<CveDatabase> logger)
    {
        _logger = logger;
        DefaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAudit", "cve", "cve.db");
    }

    public string DefaultPath { get; }

    public SqliteConnection OpenOrCreate(string? path = null)
    {
        var target = path ?? DefaultPath;
        var dir = Path.GetDirectoryName(target);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var connStr = new SqliteConnectionStringBuilder
        {
            DataSource = target,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();

        var conn = new SqliteConnection(connStr);
        conn.Open();
        EnsureSchema(conn);
        return conn;
    }

    public static DateTimeOffset? GetLastSync(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key='last_sync'";
        var raw = cmd.ExecuteScalar() as string;
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }
        return DateTimeOffset.TryParse(raw, out var dto) ? dto : null;
    }

    private void EnsureSchema(SqliteConnection conn)
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream(SchemaResource)
            ?? throw new InvalidOperationException("Embedded resource missing: " + SchemaResource);
        using var reader = new StreamReader(stream);
        var sql = reader.ReadToEnd();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
        _logger.LogDebug("CVE schema ensured at {Path}", conn.DataSource);
    }
}
