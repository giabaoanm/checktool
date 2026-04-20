namespace SecAudit.Modules.LogForensics.Models;

/// <summary>
/// User-configured parameters for a single forensics run. Built by the UI page and passed
/// to <c>LogForensicsEngine.RunAsync</c>. Nothing is persisted long-term — credentials
/// live only for the duration of the session (see SSH source).
/// </summary>
public sealed class ForensicsSettings
{
    public ForensicsSourceKind SourceKind { get; set; } = ForensicsSourceKind.LocalFolder;

    // --- Common knobs ---
    public DateTimeOffset? FromUtc { get; set; }
    public DateTimeOffset? ToUtc { get; set; }

    /// <summary>Comma-separated account names considered legitimate; anything else triggers UnknownLogon.</summary>
    public string UserWhitelist { get; set; } = string.Empty;

    /// <summary>Comma-separated CIDR list treated as "internal"; logons from outside raise RemoteAccess.</summary>
    public string InternalCidrs { get; set; } = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12";

    // --- Mode A: local folder/files ---
    public string LocalPath { get; set; } = string.Empty;
    public bool LocalRecursive { get; set; } = true;

    // --- Mode B: Windows Event Log live channel ---
    public string EventLogChannel { get; set; } = "Security";
    public string? EvtxFile { get; set; }

    // --- Mode C: SSH/SFTP remote ---
    public string SshHost { get; set; } = string.Empty;
    public int SshPort { get; set; } = 22;
    public string SshUsername { get; set; } = string.Empty;
    public string? SshPassword { get; set; }      // kept only in RAM for session
    public string? SshPrivateKeyPath { get; set; }
    public string? SshPrivateKeyPassphrase { get; set; }
    public string SshRemotePath { get; set; } = "/var/log/";
    public bool SshRecursive { get; set; }
    public int SshMaxFileBytes { get; set; } = 50 * 1024 * 1024; // 50 MB cap per file

    /// <summary>Root under %LOCALAPPDATA%\SecAudit\forensics\&lt;session-id&gt; for evidence archive.</summary>
    public string EvidenceRoot { get; set; } = string.Empty;
}

public enum ForensicsSourceKind
{
    LocalFolder = 0,
    WindowsEventLog = 1,
    SshRemote = 2
}
