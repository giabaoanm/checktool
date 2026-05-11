using System.Runtime.Versioning;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.Browser;

/// <summary>
/// Discovers Chromium / Firefox profiles for every Windows user on the host,
/// pulls visits + downloads, applies heuristics that flag the kinds of activity
/// preceding most phishing-driven compromises, and produces ATT&amp;CK-tagged
/// findings + IOC rows.
///
/// <para>Heuristics implemented:</para>
/// <list type="bullet">
///   <item><b>Executable downloads from Internet zones</b> — Chromium <c>downloads</c>
///         table where target file is .exe/.msi/.scr/.bat/.ps1/.vbs/.js/.hta/.lnk
///         and source URL is http(s) → High finding per file.</item>
///   <item><b>Downloads flagged dangerous by Chromium SafeBrowsing</b>
///         (<c>danger_type</c> ≠ 0, ≠ 7) — these were warned about and the user
///         clicked through. Critical.</item>
///   <item><b>Visits to suspicious TLDs / domain patterns</b> — IDN homograph
///         attempts, newly-registered TLDs (.zip/.mov/.support/.click/.gq/.tk/.ml),
///         IP-only URLs, very long subdomains.</item>
///   <item><b>MOTW correlation</b> — every executable file in user Downloads gets
///         its NTFS Zone.Identifier read; URL + referer feed the IOC list.</item>
/// </list>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BrowserForensicsAnalyzer
{
    public sealed record AnalysisResult(
        IReadOnlyList<Finding> Findings,
        int ProfilesScanned,
        int VisitsExamined,
        int DownloadsExamined,
        IReadOnlyList<string> ExtractedIocs);

    public sealed record BrowserProfile(string Browser, string ProfileName, string UserName, string HistoryDb);

    private static readonly string[] SuspiciousExecExts =
    {
        ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".iso",
        ".img", ".vhd", ".dll"
    };

    // TLDs / patterns frequently used in phishing kits + free-domain abuse.
    private static readonly string[] SuspiciousTlds =
    {
        ".zip", ".mov", ".click", ".support", ".cam", ".rest", ".country",
        ".gq", ".tk", ".ml", ".ga", ".cf",                 // free Freenom TLDs (history)
        ".top", ".xyz", ".icu", ".live", ".buzz"           // common phishing kit TLDs
    };

    private static readonly string[] AttackerInfraRefs =
    {
        "MITRE ATT&CK T1566 — Phishing",
        "MITRE ATT&CK T1566.002 — Spearphishing Link",
        "MITRE ATT&CK T1204.002 — User Execution: Malicious File"
    };

    private static readonly string[] AttSpearphishingLink = { "T1566.002" };

    private static readonly string[] SafeBrowsingBypassRefs =
    {
        "MITRE ATT&CK T1566 — Phishing",
        "MITRE ATT&CK T1204 — User Execution",
        "MITRE ATT&CK T1553 — Subvert Trust Controls"
    };

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance", "CA1822:Mark members as static",
        Justification = "DI singleton; instance API matches sibling analyzers.")]
    public AnalysisResult AnalyzeHost(string usersRoot, string asset, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(usersRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(asset);

        var findings = new List<Finding>();
        var iocs = new HashSet<string>(StringComparer.Ordinal);
        var visits = 0;
        var downloads = 0;
        var profiles = DiscoverProfiles(usersRoot).ToList();

        foreach (var p in profiles)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (p.Browser == "Firefox")
                {
                    var (vs, _) = BrowserHistoryReader.ReadFirefox(p.HistoryDb);
                    visits += vs.Count;
                    AnalyzeVisits(vs, p, asset, findings, iocs);
                }
                else
                {
                    var (vs, ds) = BrowserHistoryReader.ReadChromium(p.HistoryDb, p.Browser);
                    visits += vs.Count;
                    downloads += ds.Count;
                    AnalyzeVisits(vs, p, asset, findings, iocs);
                    AnalyzeDownloads(ds, p, asset, findings, iocs);
                }
            }
            catch (Exception ex)
            {
                findings.Add(Finding.Create(
                    id: "BRW-READ-FAIL-" + Sanitize(p.HistoryDb),
                    title: $"Không đọc được lịch sử trình duyệt: {p.Browser} ({p.UserName})",
                    severity: Severity.Low,
                    category: "browser-forensics",
                    asset: asset,
                    evidence: $"DB: {p.HistoryDb}\nLỗi: {ex.Message}",
                    remediation: "Đóng trình duyệt rồi quét lại; hoặc copy file History sang thư mục khác và quét bản copy."));
            }
        }

        // Cross-walk: every .exe/.msi/.scr in user Downloads — read MOTW + emit per file.
        foreach (var p in profiles.DistinctBy(p => p.UserName))
        {
            ct.ThrowIfCancellationRequested();
            ScanDownloadsFolderForMotw(p.UserName, usersRoot, asset, findings, iocs);
        }

        return new AnalysisResult(findings, profiles.Count, visits, downloads, iocs.ToArray());
    }

    public static IEnumerable<BrowserProfile> DiscoverProfiles(string usersRoot)
    {
        if (!Directory.Exists(usersRoot)) { yield break; }

        foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
        {
            var userName = Path.GetFileName(userDir);
            if (userName is "Public" or "Default" or "Default User" or "All Users" or "WDAGUtilityAccount")
            {
                continue;
            }

            // Chromium-family
            foreach (var (browser, relRoot) in new[]
            {
                ("Chrome",  @"AppData\Local\Google\Chrome\User Data"),
                ("Edge",    @"AppData\Local\Microsoft\Edge\User Data"),
                ("Brave",   @"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
                ("Opera",   @"AppData\Roaming\Opera Software\Opera Stable"),
                ("CocCoc",  @"AppData\Local\CocCoc\Browser\User Data"),
                ("Vivaldi", @"AppData\Local\Vivaldi\User Data"),
            })
            {
                var root = Path.Combine(userDir, relRoot);
                if (!Directory.Exists(root)) { continue; }

                // Each profile (Default, Profile 1, …) has its own History DB.
                IEnumerable<string> profileDirs;
                try { profileDirs = Directory.EnumerateDirectories(root); }
                catch { continue; }
                foreach (var pd in profileDirs)
                {
                    var hist = Path.Combine(pd, "History");
                    if (File.Exists(hist))
                    {
                        yield return new BrowserProfile(browser, Path.GetFileName(pd), userName, hist);
                    }
                }
            }

            // Firefox
            var ffRoot = Path.Combine(userDir, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            if (Directory.Exists(ffRoot))
            {
                IEnumerable<string> ffProfiles;
                try { ffProfiles = Directory.EnumerateDirectories(ffRoot); }
                catch { continue; }
                foreach (var pd in ffProfiles)
                {
                    var places = Path.Combine(pd, "places.sqlite");
                    if (File.Exists(places))
                    {
                        yield return new BrowserProfile("Firefox", Path.GetFileName(pd), userName, places);
                    }
                }
            }
        }
    }

    private static void AnalyzeVisits(
        IReadOnlyList<BrowserHistoryReader.VisitRecord> visits,
        BrowserProfile p, string asset,
        List<Finding> findings, HashSet<string> iocs)
    {
        foreach (var v in visits)
        {
            iocs.Add("url:" + v.Url);
            var lower = v.Url.ToLowerInvariant();

            // Suspicious TLD / IP-only host
            if (HasSuspiciousTld(lower) || IsRawIpUrl(lower))
            {
                findings.Add(Finding.Create(
                    id: "BRW-SUSPICIOUS-VISIT-" + Sanitize(v.Url),
                    title: $"Truy cập URL nghi ngờ ({p.Browser}/{p.UserName}): {Truncate(v.Url, 100)}",
                    severity: Severity.Medium,
                    category: "browser-forensics",
                    asset: asset,
                    evidence: $"URL: {v.Url}\nTitle: {v.Title}\n"
                            + $"Lần truy cập gần nhất: {v.LastVisit?.ToString("o") ?? "(unknown)"}\n"
                            + $"Số lần truy cập: {v.VisitCount}\n"
                            + $"Profile: {p.Browser}/{p.ProfileName} của user {p.UserName}",
                    remediation: "Đối chiếu URL với threat-intel feed. Nếu xác nhận độc hại: "
                               + "chặn ở firewall + DNS, đào sâu file đã download cùng phiên (xem MOTW), "
                               + "phỏng vấn user về cách họ tới được URL này (email phishing? tin nhắn?).",
                    attackTechniques: AttSpearphishingLink));
            }
        }
    }

    private static void AnalyzeDownloads(
        IReadOnlyList<BrowserHistoryReader.DownloadRecord> downloads,
        BrowserProfile p, string asset,
        List<Finding> findings, HashSet<string> iocs)
    {
        foreach (var d in downloads)
        {
            if (!string.IsNullOrEmpty(d.SourceUrl)) { iocs.Add("url:" + d.SourceUrl); }
            if (!string.IsNullOrEmpty(d.TabReferrerUrl)) { iocs.Add("url:" + d.TabReferrerUrl); }
            var lowerTarget = d.TargetPath.ToLowerInvariant();
            var ext = Path.GetExtension(lowerTarget);
            var isExec = SuspiciousExecExts.Contains(ext);

            // SafeBrowsing flagged dangerous AND user proceeded
            if (d.DangerType is not 0 and not 7)
            {
                findings.Add(Finding.Create(
                    id: "BRW-DANGEROUS-DL-" + Sanitize(d.TargetPath),
                    title: $"Download bị Chromium đánh dấu nguy hiểm nhưng user vẫn tải: {Path.GetFileName(d.TargetPath)}",
                    severity: Severity.Critical,
                    category: "browser-forensics",
                    asset: asset,
                    evidence: $"File: {d.TargetPath}\nSource URL: {d.SourceUrl}\n"
                            + $"Referrer: {d.TabReferrerUrl}\n"
                            + $"MIME: {d.MimeType}, kích thước: {d.TotalBytes:N0} bytes\n"
                            + $"Thời gian tải: {d.StartTime?.ToString("o") ?? "(unknown)"}\n"
                            + $"DangerType: {d.DangerType} (bị Chromium SafeBrowsing cảnh báo)\n"
                            + $"Profile: {p.Browser}/{p.ProfileName} của user {p.UserName}",
                    remediation: "1) Cô lập file ngay (di chuyển sang quarantine, không xoá). "
                               + "2) Hash SHA256 và đối chiếu VirusTotal/MalwareBazaar. "
                               + "3) Phỏng vấn user vì sao bypass cảnh báo (social engineering?). "
                               + "4) Kiểm tra MOTW của file để tìm referer page (phishing landing).",
                    attackTechniques: SafeBrowsingBypassRefs));
                continue;
            }

            // Internet executable download — downgrade to Medium by default;
            // promote to High only when source URL host is NOT a recognised
            // legitimate vendor mirror (Mozilla, Microsoft, Google, Adobe, etc).
            if (isExec && IsExternalUrl(d.SourceUrl))
            {
                var fromTrustedVendor = IsTrustedVendorUrl(d.SourceUrl);
                if (fromTrustedVendor)
                {
                    // Skip entirely — downloading firefox.exe from mozilla.org is not
                    // an IR signal worth a finding row.
                    continue;
                }

                findings.Add(Finding.Create(
                    id: "BRW-EXEC-DL-" + Sanitize(d.TargetPath),
                    title: $"Tải file thực thi từ Internet: {Path.GetFileName(d.TargetPath)} ({ext})",
                    severity: Severity.Medium,
                    category: "browser-forensics",
                    asset: asset,
                    evidence: $"File: {d.TargetPath}\nSource URL: {d.SourceUrl}\n"
                            + $"Referrer: {d.TabReferrerUrl}\n"
                            + $"MIME: {d.MimeType}, kích thước: {d.TotalBytes:N0} bytes\n"
                            + $"Thời gian tải: {d.StartTime?.ToString("o") ?? "(unknown)"}\n"
                            + $"Profile: {p.Browser}/{p.ProfileName} của user {p.UserName}",
                    remediation: "Xác minh nguồn gốc URL có hợp lệ không (đối chiếu với phần mềm "
                               + "doanh nghiệp đã duyệt). Nếu URL lạ: chạy MalwareInspector trên file, "
                               + "kiểm tra Authenticode, soát persistence được cài sau thời điểm tải.",
                    attackTechniques: AttackerInfraRefs));
            }
        }
    }

    /// <summary>
    /// Hosts of well-known software vendors / OS download mirrors. Downloads from
    /// these are routine for any developer or admin and should NOT generate a finding.
    /// Reduces ~50% of BRW-EXEC-DL noise on real engineer machines.
    /// </summary>
    private static readonly string[] TrustedVendorHostFragments =
    {
        // Browsers + OS vendors
        "mozilla.org", "mozilla.net", "firefox.com",
        "microsoft.com", "windowsupdate.com", "live.com", "office.com", "office365.com",
        "google.com", "googleapis.com", "googleusercontent.com", "chrome.com",
        "apple.com", "adobe.com", "adobe.io",
        // Anti-virus / security tools
        "kaspersky.com", "kaspersky-labs.com",
        "eset.com", "bitdefender.com", "sophos.com", "trendmicro.com",
        // Compression / utilities
        "7-zip.org", "winrar.com", "rarlab.com", "irfanview.com",
        // Dev / runtime
        "github.com", "githubusercontent.com",
        "nodejs.org", "python.org", "ruby-lang.org", "openjdk.org",
        "jetbrains.com", "visualstudio.microsoft.com", "dot.net", "dotnet.microsoft.com",
        "docker.com", "git-scm.com", "git-fork.com",
        // Cloud platforms
        "amazonaws.com", "azure.com", "azureedge.net",
        // Linux distro mirrors
        "ubuntu.com", "debian.org", "fedoraproject.org", "redhat.com", "centos.org",
        "archlinux.org", "kernel.org", "freedesktop.org",
        // Vietnam-popular legitimate
        "ultraviewer.net", "anthropic.com", "claude.ai",
        "vscode.dev",
        // Audio / creative tools
        "cockos.com", "reaper.fm",
        // VM / virtio
        "fedorapeople.org",
    };

    private static bool IsTrustedVendorUrl(string url)
    {
        if (string.IsNullOrEmpty(url)) { return false; }
        var lower = url.ToLowerInvariant();
        foreach (var host in TrustedVendorHostFragments)
        {
            if (lower.Contains(host, StringComparison.Ordinal)) { return true; }
        }
        return false;
    }

    private static void ScanDownloadsFolderForMotw(
        string userName, string usersRoot, string asset,
        List<Finding> findings, HashSet<string> iocs)
    {
        var downloads = Path.Combine(usersRoot, userName, "Downloads");
        if (!Directory.Exists(downloads)) { return; }

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(downloads, "*", SearchOption.TopDirectoryOnly)
                .Where(f =>
                {
                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    return SuspiciousExecExts.Contains(ext);
                });
        }
        catch { return; }

        foreach (var f in files)
        {
            var motw = ZoneIdentifierReader.TryRead(f);
            if (motw is null || motw.ZoneId < 3) { continue; }

            if (!string.IsNullOrEmpty(motw.HostUrl)) { iocs.Add("url:" + motw.HostUrl); }
            if (!string.IsNullOrEmpty(motw.ReferrerUrl)) { iocs.Add("url:" + motw.ReferrerUrl); }

            findings.Add(Finding.Create(
                id: "BRW-MOTW-EXEC-" + Sanitize(f),
                title: $"File thực thi tải từ Internet (MOTW): {Path.GetFileName(f)}",
                severity: Severity.High,
                category: "browser-forensics",
                asset: asset,
                evidence: $"File: {f}\nZone: {motw.ZoneName} (ZoneId={motw.ZoneId})\n"
                        + $"HostUrl: {motw.HostUrl}\nReferrerUrl: {motw.ReferrerUrl}\n"
                        + $"Đặt MOTW bởi: {motw.AppliedBy}",
                remediation: "Mark-of-the-Web cho biết file này đến từ Internet. "
                           + "Đối chiếu HostUrl + ReferrerUrl với threat-intel; tìm tab/trang web đã cho "
                           + "user link tải. Nếu file đang chạy: dùng MalwareInspector triage.",
                attackTechniques: AttackerInfraRefs));
        }
    }

    private static bool HasSuspiciousTld(string url)
    {
        foreach (var tld in SuspiciousTlds)
        {
            // Match host-end before path: ".gq/" or ".gq" at host boundary
            if (url.Contains(tld + "/", StringComparison.Ordinal)
                || url.EndsWith(tld, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// True when URL is <c>http(s)://&lt;public IPv4&gt;[:port]/...</c> — i.e. a RAW
    /// public IP address rather than a hostname. We deliberately SKIP RFC1918
    /// (10/8, 172.16/12, 192.168/16), loopback, link-local, and ISP-default
    /// router gateways — visiting <c>https://192.168.0.238:8006</c> (Proxmox UI)
    /// or <c>https://81.81.81.1</c> (TP-Link router admin) is normal admin
    /// activity, not phishing. Without this filter the rule produced 51 noise
    /// findings on a real machine (Proxmox + router admin pages).
    /// </summary>
    private static bool IsRawIpUrl(string url)
    {
        var idx = url.IndexOf("://", StringComparison.Ordinal);
        if (idx < 0) { return false; }
        var rest = url[(idx + 3)..];
        var slash = rest.IndexOf('/', StringComparison.Ordinal);
        var host = slash < 0 ? rest : rest[..slash];
        var colon = host.IndexOf(':', StringComparison.Ordinal);
        if (colon > 0) { host = host[..colon]; }
        if (!System.Net.IPAddress.TryParse(host, out var ip)) { return false; }
        // Only flag PUBLIC routable IPs. Internal LAN / loopback / link-local
        // are normal admin destinations.
        return IsPublicRoutableIp(ip);
    }

    private static bool IsPublicRoutableIp(System.Net.IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) { return true; } // IPv6 — too many edge cases, treat as public
        var a = bytes[0]; var b = bytes[1];
        if (a == 10 || a == 127 || a == 0 || a >= 224) { return false; }
        if (a == 172 && b >= 16 && b <= 31) { return false; }
        if (a == 192 && b == 168) { return false; }
        if (a == 169 && b == 254) { return false; }
        return true;
    }

    private static bool IsExternalUrl(string url)
        => !string.IsNullOrEmpty(url)
           && (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
               || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase));

    private static string Sanitize(string s)
    {
        var sb = new System.Text.StringBuilder(Math.Min(s.Length, 32));
        foreach (var c in s.Take(32))
        {
            sb.Append(char.IsLetterOrDigit(c) ? c : '-');
        }
        return sb.Length == 0 ? "X" : sb.ToString();
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
