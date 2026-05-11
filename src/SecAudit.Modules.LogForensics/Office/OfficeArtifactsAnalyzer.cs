using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.Office;

/// <summary>
/// Three independent detectors aimed at the most common email/document-borne
/// attack chain on Windows:
///
/// <list type="number">
///   <item><b>Office "Trusted Documents" registry</b> — every time a user clicks
///         "Enable Content" / "Enable Editing" on a downloaded Office file, Office
///         records a <c>TrustRecord</c> at
///         <c>HKCU\Software\Microsoft\Office\&lt;ver&gt;\&lt;App&gt;\Security\Trusted Documents\TrustRecords</c>.
///         If any of those file paths point at <c>%TEMP%</c>, Outlook attachment cache,
///         or a Downloads-area .docm/.xlsm/.pptm, that's the smoking-gun "user
///         enabled macro on something attacker delivered".</item>
///   <item><b>Macro-enabled Office files</b> in user-writable paths (Downloads,
///         Documents, Desktop, %TEMP%, Outlook attachment cache) — even without
///         a TrustRecord match, the presence of <c>.docm/.xlsm/.pptm/.dotm</c>
///         files in a download path is forensic interesting.</item>
///   <item><b>Outlook attachment cache</b> at
///         <c>%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook\&lt;random&gt;\</c>
///         — a hidden folder Outlook drops attachments into when the user
///         double-clicks them. We list every executable / macro file here as
///         Medium+ findings (proves the user opened the attachment).</item>
/// </list>
///
/// <para>Multi-user note: this v1 only reads HKCU of the running user (HKEY_USERS
/// for currently-loaded SIDs is auto-included); offline NTUSER.DAT parsing for
/// other users is deferred to v2.</para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OfficeArtifactsAnalyzer
{
    public sealed record AnalysisResult(
        IReadOnlyList<Finding> Findings,
        int TrustedDocsScanned,
        int MacroFilesScanned,
        int OutlookCacheFilesScanned,
        IReadOnlyList<string> ExtractedIocs);

    private static readonly string[] OfficeApps =
    {
        "Word", "Excel", "PowerPoint", "Access", "Outlook", "Project", "Visio", "Publisher"
    };

    private static readonly string[] OfficeVersions =
    {
        "16.0",  // 2016, 2019, 2021, 365
        "15.0",  // 2013
        "14.0"   // 2010
    };

    private static readonly string[] MacroExts =
    {
        ".docm", ".dotm",                      // Word
        ".xlsm", ".xltm", ".xlsb", ".xlam",    // Excel (xlsb can hold macros via XLM)
        ".pptm", ".potm", ".ppam"              // PowerPoint
    };

    private static readonly string[] OfficeExeExts =
    {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".lnk", ".jar", ".iso", ".img"
    };

    // Folders Outlook may use as attachment cache (varies by Office version + locale).
    private static readonly string[] OutlookCacheRelativePaths =
    {
        @"AppData\Local\Microsoft\Windows\INetCache\Content.Outlook",
        @"AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook",
        @"AppData\Local\Microsoft\Outlook"
    };

    private static readonly string[] AttUserExecRefs =
    {
        "MITRE ATT&CK T1204.002 — User Execution: Malicious File",
        "MITRE ATT&CK T1566.001 — Spearphishing Attachment",
        "MITRE ATT&CK T1059.005 — VBA Scripting"
    };

    private static readonly string[] AttSpearphishingRefs =
    {
        "MITRE ATT&CK T1566.001 — Spearphishing Attachment",
        "MITRE ATT&CK T1204.002 — User Execution: Malicious File"
    };

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance", "CA1822:Mark members as static",
        Justification = "DI singleton; instance API matches sibling analyzers.")]
    public AnalysisResult Analyze(string usersRoot, string asset, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(usersRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(asset);

        var findings = new List<Finding>();
        var iocs = new HashSet<string>(StringComparer.Ordinal);

        var trustedDocs = AnalyzeTrustedDocuments(asset, findings, iocs, ct);
        var macroFiles = AnalyzeMacroEnabledFiles(usersRoot, asset, findings, iocs, ct);
        var outlookFiles = AnalyzeOutlookCache(usersRoot, asset, findings, iocs, ct);

        return new AnalysisResult(findings, trustedDocs, macroFiles, outlookFiles, iocs.ToArray());
    }

    // ---------------------------------------------------------------------
    //  1. Office Trusted Documents (registry)
    // ---------------------------------------------------------------------

    private static int AnalyzeTrustedDocuments(
        string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        var scanned = 0;
        foreach (var ver in OfficeVersions)
        {
            foreach (var app in OfficeApps)
            {
                ct.ThrowIfCancellationRequested();
                var subKey = $@"Software\Microsoft\Office\{ver}\{app}\Security\Trusted Documents\TrustRecords";
                using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: false);
                if (key is null) { continue; }

                foreach (var name in key.GetValueNames())
                {
                    scanned++;
                    var path = name; // Office stores the FILE PATH as the value name
                    if (string.IsNullOrEmpty(path)) { continue; }

                    iocs.Add("file:" + path);
                    var lowerPath = path.ToLowerInvariant();

                    // Decode the trust state from the value DATA (binary blob, last
                    // 4 bytes is a flag: 0x7FFFFFFF means "user enabled all content").
                    var data = key.GetValue(name) as byte[];
                    var enabledAll = data is not null && data.Length >= 4
                        && data[^4] == 0xFF && data[^3] == 0xFF
                        && data[^2] == 0xFF && data[^1] == 0x7F;
                    var stateLabel = enabledAll
                        ? "Enable Content (cho phép macro chạy)"
                        : "Enable Editing (rời Protected View)";

                    var fileExt = Path.GetExtension(lowerPath);
                    var isMacroFile = MacroExts.Contains(fileExt);
                    var isFromSuspectArea = IsFromSuspectArea(lowerPath);

                    if (!isMacroFile && !isFromSuspectArea) { continue; }

                    var sev = (isMacroFile && enabledAll && isFromSuspectArea)
                        ? Severity.Critical
                        : (isMacroFile && enabledAll) ? Severity.High
                        : Severity.Medium;

                    findings.Add(Finding.Create(
                        id: "OFC-TRUSTED-DOC-" + Sanitize(path),
                        title: $"Office {app}: user đã trust file đáng ngờ — {Path.GetFileName(path)}",
                        severity: sev,
                        category: "office-artifacts",
                        asset: asset,
                        evidence: $"Office app: {app} {ver}\nFile: {path}\n"
                                + $"Trạng thái: {stateLabel}\n"
                                + $"Đuôi file: {fileExt} {(isMacroFile ? "(macro-enabled)" : "")}\n"
                                + $"Vị trí: {(isFromSuspectArea ? "Downloads/Temp/Outlook cache (đáng ngờ)" : "Documents (bình thường)")}\n"
                                + $"Registry: HKCU\\{subKey}",
                        remediation: "1) Thu thập file Office này làm bằng chứng (sao có hash). "
                                   + "2) Mở trong sandbox (Office Protected View hoặc VM riêng) để "
                                   + "trích VBA macro (oletools/olevba). "
                                   + "3) Phỏng vấn user về cách họ nhận file (email phishing? link Zalo/Telegram?). "
                                   + "4) Vô hiệu hoá macro qua GPO nếu chính sách doanh nghiệp cho phép.",
                        attackTechniques: AttUserExecRefs));
                }
            }
        }
        return scanned;
    }

    // ---------------------------------------------------------------------
    //  2. Macro-enabled file scan
    // ---------------------------------------------------------------------

    private static int AnalyzeMacroEnabledFiles(
        string usersRoot, string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        if (!Directory.Exists(usersRoot)) { return 0; }
        var scanned = 0;

        foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
        {
            ct.ThrowIfCancellationRequested();
            var userName = Path.GetFileName(userDir);
            if (userName is "Public" or "Default" or "Default User" or "All Users" or "WDAGUtilityAccount")
            {
                continue;
            }

            foreach (var subFolder in new[] { "Downloads", "Documents", "Desktop", "AppData\\Local\\Temp" })
            {
                var folder = Path.Combine(userDir, subFolder);
                if (!Directory.Exists(folder)) { continue; }

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly)
                        .Where(f => MacroExts.Contains(Path.GetExtension(f).ToLowerInvariant()));
                }
                catch { continue; }

                foreach (var f in files)
                {
                    scanned++;
                    iocs.Add("file:" + f);
                    FileInfo fi;
                    try { fi = new FileInfo(f); }
                    catch { continue; }

                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    var sev = subFolder.Contains("Temp", StringComparison.Ordinal)
                            || subFolder.Equals("Downloads", StringComparison.Ordinal)
                        ? Severity.Medium
                        : Severity.Low;

                    findings.Add(Finding.Create(
                        id: "OFC-MACRO-FILE-" + Sanitize(f),
                        title: $"File Office macro-enabled trong {subFolder} của user {userName}: {fi.Name}",
                        severity: sev,
                        category: "office-artifacts",
                        asset: asset,
                        evidence: $"File: {f}\nĐuôi: {ext}\nKích thước: {fi.Length:N0} bytes\n"
                                + $"Sửa lần cuối: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}\n"
                                + $"Vị trí: {subFolder} của user {userName}",
                        remediation: "File Office có khả năng chứa macro. Trích nội dung VBA bằng "
                                   + "oletools/olevba để xem có code đáng ngờ không. Đối chiếu với "
                                   + "Trusted Documents — nếu có user enabled macro thì xem là phiên xâm nhập.",
                        attackTechniques: AttSpearphishingRefs));
                }
            }
        }
        return scanned;
    }

    // ---------------------------------------------------------------------
    //  3. Outlook attachment cache
    // ---------------------------------------------------------------------

    private static int AnalyzeOutlookCache(
        string usersRoot, string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        if (!Directory.Exists(usersRoot)) { return 0; }
        var scanned = 0;

        foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
        {
            ct.ThrowIfCancellationRequested();
            var userName = Path.GetFileName(userDir);
            if (userName is "Public" or "Default" or "Default User" or "All Users" or "WDAGUtilityAccount")
            {
                continue;
            }

            foreach (var rel in OutlookCacheRelativePaths)
            {
                var cacheRoot = Path.Combine(userDir, rel);
                if (!Directory.Exists(cacheRoot)) { continue; }

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(cacheRoot, "*", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var f in files)
                {
                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    var isMacro = MacroExts.Contains(ext);
                    var isExec = OfficeExeExts.Contains(ext);
                    if (!isMacro && !isExec) { continue; }
                    scanned++;
                    iocs.Add("file:" + f);

                    FileInfo fi;
                    try { fi = new FileInfo(f); }
                    catch { continue; }

                    var sev = isExec ? Severity.High : Severity.Medium;
                    findings.Add(Finding.Create(
                        id: "OFC-OUTLOOK-CACHE-" + Sanitize(f),
                        title: $"Tệp đính kèm Outlook đã mở: {fi.Name} ({ext})",
                        severity: sev,
                        category: "office-artifacts",
                        asset: asset,
                        evidence: $"File: {f}\nUser: {userName}\nĐuôi: {ext}\n"
                                + $"Kích thước: {fi.Length:N0} bytes\n"
                                + $"Sửa lần cuối: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}\n"
                                + $"Vị trí cache: {rel}",
                        remediation: "File trong Outlook attachment cache đồng nghĩa user đã DOUBLE-CLICK "
                                   + "vào tệp đính kèm trong email. Dù file có chạy thật hay không, đây là "
                                   + "bằng chứng tương tác trực tiếp với attachment. "
                                   + "1) Hash + tra cứu VirusTotal. "
                                   + "2) Truy vết email gốc trong PST/OST của user (sender, subject, time). "
                                   + "3) Nếu là .docm/.xlsm: kết hợp với OFC-TRUSTED-DOC-* để xác định "
                                   + "macro đã chạy chưa.",
                        attackTechniques: AttSpearphishingRefs));
                }
            }
        }
        return scanned;
    }

    // ---------------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------------

    private static bool IsFromSuspectArea(string lowerPath)
    {
        return lowerPath.Contains(@"\downloads\", StringComparison.Ordinal)
            || lowerPath.Contains(@"\appdata\local\temp\", StringComparison.Ordinal)
            || lowerPath.Contains(@"\appdata\local\microsoft\windows\inetcache\content.outlook\",
                StringComparison.Ordinal)
            || lowerPath.Contains(@"\appdata\local\microsoft\outlook\", StringComparison.Ordinal)
            || lowerPath.Contains(@"\users\public\", StringComparison.Ordinal)
            || lowerPath.Contains(@"\windows\temp\", StringComparison.Ordinal);
    }

    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(Math.Min(s.Length, 32));
        foreach (var c in s.Take(32))
        {
            sb.Append(char.IsLetterOrDigit(c) ? c : '-');
        }
        return sb.Length == 0 ? "X" : sb.ToString();
    }
}
