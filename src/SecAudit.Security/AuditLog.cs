using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SecAudit.Security;

/// <summary>
/// Append-only JSONL audit log with SHA-256 hash chain.
/// ECDSA signing is wired in Iteration 5; this stub keeps the chain only.
/// Path: %PROGRAMDATA%\SecAudit\audit\audit-YYYYMMDD.log
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuditLog
{
    private static readonly object SyncRoot = new();
    private readonly string _baseFolder;

    public AuditLog()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SecAudit", "audit"))
    {
    }

    public AuditLog(string baseFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseFolder);
        _baseFolder = baseFolder;
        Directory.CreateDirectory(_baseFolder);
    }

    public string CurrentLogPath
        => Path.Combine(_baseFolder, $"audit-{DateTime.UtcNow:yyyyMMdd}.log");

    public void Write(string eventName, IReadOnlyDictionary<string, string>? payload = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);

        var record = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ts"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            ["machine"] = Environment.MachineName,
            ["user_sid"] = TryGetCurrentSid(),
            ["event"] = eventName,
            ["payload"] = payload ?? new Dictionary<string, string>()
        };

        lock (SyncRoot)
        {
            var path = CurrentLogPath;
            var prevHash = ComputePrevHash(path);
            record["prev_hash"] = prevHash;

            var json = JsonSerializer.Serialize(record);
            using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.WriteLine(json);
        }
    }

    private static string ComputePrevHash(string path)
    {
        if (!File.Exists(path))
        {
            return new string('0', 64);
        }
        // Cheap implementation: hash the entire file. Replace with incremental hash later if perf matters.
        using var fs = File.OpenRead(path);
        var hash = SHA256.HashData(fs);
        return Convert.ToHexString(hash);
    }

    private static string TryGetCurrentSid()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return id.User?.Value ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }
}
