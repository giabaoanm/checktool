using SecAudit.Modules.SystemInfo.Models;

namespace SecAudit.Modules.RemoteAccess.Detectors;

/// <summary>
/// Pure-data detector: scans the shared <see cref="InstalledSoftware"/> list (collected
/// by the SystemInfo module) for known remote-access / unattended-access tooling.
///
/// We classify, we never block. A SOC operator may have installed AnyDesk legitimately —
/// the finding is informational and the operator decides whether it belongs on the host.
/// </summary>
public sealed class RemoteAccessToolDetector
{
    public sealed record DetectedTool(string ProductName, string Vendor, string Severity, string Why);

    private static readonly (string keyword, string vendor, string severity, string why)[] Catalogue =
    {
        ("anydesk",       "AnyDesk Software GmbH", "High",   "Unattended remote access; common in tech-support scams and post-compromise toolkits."),
        ("teamviewer",    "TeamViewer",            "Medium", "Unattended remote access; abused in targeted intrusions."),
        ("rustdesk",      "RustDesk",              "High",   "Open-source unattended remote access; popular with attackers because it self-hosts."),
        ("ultravnc",      "UltraVNC",              "High",   "Plaintext-capable VNC; flagged because attackers often deploy portable VNC."),
        ("tightvnc",      "TightVNC",              "Medium", "VNC server — should not be installed on workstations unless explicitly required."),
        ("realvnc",       "RealVNC",               "Medium", "VNC server — should not be installed on workstations unless explicitly required."),
        ("screenconnect", "ConnectWise",           "Medium", "ScreenConnect/ConnectWise Control — frequently abused in MSP supply-chain attacks."),
        ("connectwise control", "ConnectWise",     "Medium", "ScreenConnect/ConnectWise Control — frequently abused in MSP supply-chain attacks."),
        ("splashtop",     "Splashtop",             "Medium", "Unattended remote access tool."),
        ("logmein",       "LogMeIn",               "Medium", "Unattended remote access tool."),
        ("gotomypc",      "LogMeIn",               "Medium", "Unattended remote access tool."),
        ("supremo",       "Nanosystems",           "Medium", "Unattended remote access tool."),
        ("aeroadmin",     "AeroAdmin",             "High",   "Portable remote-access tool frequently bundled in commodity malware."),
        ("ammyy",         "Ammyy Group",           "High",   "Ammyy Admin — historically signed by malware operators; no legitimate enterprise use case."),
        ("dwservice",     "DWAgent",               "Medium", "Unattended remote access tool."),
        ("netsupport manager", "NetSupport",       "High",   "NetSupport RAT is a documented post-exploitation tool when not part of a managed install."),
        ("remoteutilities", "Remote Utilities",    "Medium", "Unattended remote access tool."),
        ("pcanywhere",    "Symantec",              "Medium", "Legacy unattended remote access; should not be present on modern endpoints.")
    };

    public static IReadOnlyList<DetectedTool> Detect(IReadOnlyList<InstalledSoftware> software)
    {
        if (software is null || software.Count == 0)
        {
            return Array.Empty<DetectedTool>();
        }

        var hits = new List<DetectedTool>();
        foreach (var sw in software)
        {
            if (string.IsNullOrEmpty(sw.DisplayName))
            {
                continue;
            }
            var name = sw.DisplayName.ToLowerInvariant();
            foreach (var (kw, vendor, severity, why) in Catalogue)
            {
                if (name.Contains(kw, StringComparison.Ordinal))
                {
                    hits.Add(new DetectedTool(sw.DisplayName, vendor, severity, why));
                    break;
                }
            }
        }
        return hits;
    }
}
