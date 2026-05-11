using System.Runtime.Versioning;

namespace SecAudit.Modules.LogForensics.Browser;

/// <summary>
/// Reads the NTFS Alternate Data Stream <c>:Zone.Identifier</c> that Windows
/// (SmartScreen / Attachment Manager / Chromium / Edge) attaches to files
/// downloaded from the Internet — the so-called Mark-of-the-Web (MOTW).
///
/// <para>The stream is INI-format with a <c>[ZoneTransfer]</c> section:</para>
/// <code>
/// [ZoneTransfer]
/// ZoneId=3
/// HostUrl=https://attacker.example/payload.exe
/// ReferrerUrl=https://google.com/search?q=...
/// LastWriterPackageFamilyName=Microsoft.MicrosoftEdge_8wekyb3d8bbwe
/// </code>
///
/// <para>Zone IDs (Windows IZoneIdentifier semantics):
/// 0=Local, 1=Intranet, 2=Trusted, 3=Internet, 4=Untrusted.</para>
///
/// <para>Forensic value: when SecAudit finds a malicious payload on disk, MOTW
/// tells us EXACTLY which URL the user downloaded it from + the referer page
/// (often the phishing landing page). That's the missing link between
/// "payload on disk" and "user behaviour".</para>
/// </summary>
[SupportedOSPlatform("windows")]
public static class ZoneIdentifierReader
{
    public sealed record MotwInfo(
        string FilePath,
        int ZoneId,
        string ZoneName,
        string HostUrl,
        string ReferrerUrl,
        string AppliedBy);

    public static MotwInfo? TryRead(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return null;
        }
        var streamPath = filePath + ":Zone.Identifier";
        try
        {
            // Opening an ADS through standard .NET FileStream works on NTFS — the
            // colon-suffix syntax is honoured by CreateFile under the hood.
            using var fs = new FileStream(streamPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var sr = new StreamReader(fs);
            var content = sr.ReadToEnd();

            int zoneId = 3; // default = Internet
            string host = string.Empty;
            string referer = string.Empty;
            string applied = string.Empty;
            foreach (var raw in content.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('[') || line.StartsWith(';')) { continue; }
                var eq = line.IndexOf('=', StringComparison.Ordinal);
                if (eq < 1) { continue; }
                var k = line[..eq].Trim();
                var v = line[(eq + 1)..].Trim();
                if (k.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(v, out var z)) { zoneId = z; }
                else if (k.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) { host = v; }
                else if (k.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) { referer = v; }
                else if (k.Equals("LastWriterPackageFamilyName", StringComparison.OrdinalIgnoreCase))
                {
                    applied = v;
                }
            }

            return new MotwInfo(
                FilePath: filePath,
                ZoneId: zoneId,
                ZoneName: zoneId switch
                {
                    0 => "Local",
                    1 => "Intranet",
                    2 => "Trusted",
                    3 => "Internet",
                    4 => "Untrusted",
                    _ => $"Zone={zoneId}"
                },
                HostUrl: host,
                ReferrerUrl: referer,
                AppliedBy: applied);
        }
        catch (FileNotFoundException)
        {
            return null;       // No MOTW = file is from local/trusted source
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>True if the file has a MOTW pointing at Internet/Untrusted zones.</summary>
    public static bool IsFromInternet(string filePath)
    {
        var motw = TryRead(filePath);
        return motw is not null && motw.ZoneId >= 3;
    }
}
