using System.Runtime.Versioning;

namespace SecAudit.Security;

/// <summary>
/// Persists EULA acceptance in per-user app data. The shell queries this on startup and shows
/// the acceptance modal if not yet accepted.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EulaGate
{
    private const string AcceptanceMarker = "eula-accepted.marker";

    public string AcceptanceFolder { get; }

    public EulaGate()
    {
        AcceptanceFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAudit");
    }

    public bool IsAccepted()
    {
        var path = Path.Combine(AcceptanceFolder, AcceptanceMarker);
        return File.Exists(path);
    }

    public void RecordAcceptance(string userSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        Directory.CreateDirectory(AcceptanceFolder);
        var path = Path.Combine(AcceptanceFolder, AcceptanceMarker);
        var payload = $"{DateTimeOffset.UtcNow:O}\t{userSid}\t{Environment.MachineName}\r\n";
        File.WriteAllText(path, payload);
    }
}
