using System.Runtime.Versioning;
using System.Text;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.Recent;

/// <summary>
/// Walks every Windows user's Recent folder and the per-user JumpList directory
/// counting <c>.lnk</c> shortcuts. Emits findings when a shortcut points at:
///
/// <list type="bullet">
///   <item>An executable in a user-writable location (Downloads, %TEMP%,
///         %APPDATA%, Outlook attachment cache).</item>
///   <item>A hidden-name binary (<c>.crond</c>, <c>.beacon</c>) in any path.</item>
///   <item>A target on a removable drive (USB) — the user's only real evidence
///         that data was opened from a thumb drive.</item>
///   <item>An LNK whose <c>Arguments</c> contain encoded PowerShell or
///         <c>cmd.exe /c</c> launchers (a classic LOLBin dropper pattern).</item>
/// </list>
///
/// <para>The Recent folder also holds the <c>AutomaticDestinations\</c> JumpLists,
/// but those are Compound File Binary (OLE) — full parsing needs a CFB library
/// and is deferred. We just count them and surface the file count + age so the
/// analyst knows how rich the JumpList artifact set is for follow-up DFIR.</para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RecentFilesAnalyzer
{
    public sealed record AnalysisResult(
        IReadOnlyList<Finding> Findings,
        int LnkFilesParsed,
        int JumpListFilesFound,
        int UsersExamined,
        IReadOnlyList<string> ExtractedIocs);

    private static readonly string[] SuspiciousExecExts =
    {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".iso", ".img"
    };

    private static readonly string[] UserWritableMarkers =
    {
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\appdata\local\",
        @"\downloads\",
        @"\users\public\",
        @"\windows\temp\",
        @"\programdata\",
        @"\appdata\local\microsoft\windows\inetcache\content.outlook\",
        @"\appdata\local\microsoft\outlook\"
    };

    private static readonly string[] HiddenBinaryHints =
    {
        @"\.crond", @"\.beacon", @"\.update", @"\.daemon", @"\.systemd_"
    };

    private static readonly string[] AttUserExecRefs =
    {
        "MITRE ATT&CK T1204.002 — User Execution: Malicious File",
        "MITRE ATT&CK T1547.009 — Boot or Logon Autostart: Shortcut Modification"
    };

    private static readonly string[] AttRemovableMediaRefs =
    {
        "MITRE ATT&CK T1091 — Replication Through Removable Media",
        "MITRE ATT&CK T1052.001 — Exfiltration Over USB"
    };

    private static readonly string[] AttLolBinRefs =
    {
        "MITRE ATT&CK T1059.001 — PowerShell",
        "MITRE ATT&CK T1059.003 — Windows Command Shell",
        "MITRE ATT&CK T1027 — Obfuscated Files or Information"
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
        var lnkParsed = 0;
        var jumpListFound = 0;
        var users = 0;

        if (!Directory.Exists(usersRoot))
        {
            return new AnalysisResult(findings, 0, 0, 0, Array.Empty<string>());
        }

        foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
        {
            ct.ThrowIfCancellationRequested();
            var userName = Path.GetFileName(userDir);
            if (userName is "Public" or "Default" or "Default User" or "All Users" or "WDAGUtilityAccount")
            {
                continue;
            }
            users++;

            var recent = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
            if (Directory.Exists(recent))
            {
                lnkParsed += ScanRecentFolder(recent, userName, asset, findings, iocs, ct);

                // JumpList automatic destinations
                var jumpAuto = Path.Combine(recent, "AutomaticDestinations");
                if (Directory.Exists(jumpAuto))
                {
                    try
                    {
                        var jl = Directory.EnumerateFiles(jumpAuto, "*.automaticDestinations-ms",
                            SearchOption.TopDirectoryOnly).ToList();
                        jumpListFound += jl.Count;
                        if (jl.Count > 0)
                        {
                            EmitJumpListSummary(jl, userName, asset, findings);
                        }
                    }
                    catch { /* perm */ }
                }
            }
        }

        return new AnalysisResult(findings, lnkParsed, jumpListFound, users, iocs.ToArray());
    }

    private static int ScanRecentFolder(
        string recent, string userName, string asset,
        List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        IEnumerable<string> lnks;
        try { lnks = Directory.EnumerateFiles(recent, "*.lnk", SearchOption.TopDirectoryOnly); }
        catch { return 0; }

        var parsed = 0;
        foreach (var lnkPath in lnks)
        {
            ct.ThrowIfCancellationRequested();
            var info = LnkFileParser.TryParse(lnkPath);
            if (info is null) { continue; }
            parsed++;

            var target = info.TargetLocalPath;
            if (string.IsNullOrEmpty(target)) { continue; }

            iocs.Add("file:" + target);
            var lower = target.ToLowerInvariant();
            var ext = Path.GetExtension(lower);

            // Pattern 1: executable in user-writable area
            var inUserWritable = false;
            string? matchedArea = null;
            foreach (var area in UserWritableMarkers)
            {
                if (lower.Contains(area, StringComparison.Ordinal))
                {
                    inUserWritable = true;
                    matchedArea = area.Trim('\\');
                    break;
                }
            }
            var isExec = SuspiciousExecExts.Contains(ext);
            if (isExec && inUserWritable)
            {
                findings.Add(MakeFinding(
                    "RCT-EXEC-USERPATH-" + Sanitize(target),
                    $"User {userName} đã mở/launch file thực thi từ {matchedArea}: {Path.GetFileName(target)}",
                    Severity.High, "recent-files", asset,
                    BuildEvidence(info, userName, "Executable trong vùng user-writable"),
                    "1) Hash file SHA256 + tra cứu VirusTotal. "
                    + "2) Phỏng vấn user về cách file đến tay (email phishing? Zalo? USB?). "
                    + "3) Đối chiếu MOTW của target để biết URL gốc.",
                    AttUserExecRefs));
            }

            // Pattern 2: hidden-name binary
            foreach (var hint in HiddenBinaryHints)
            {
                if (lower.Contains(hint, StringComparison.Ordinal))
                {
                    findings.Add(MakeFinding(
                        "RCT-HIDDEN-BIN-" + Sanitize(target),
                        $"User {userName} có shortcut tới hidden-name binary: {Path.GetFileName(target)}",
                        Severity.High, "recent-files", asset,
                        BuildEvidence(info, userName, "Tên file ẩn (.* prefix) — pattern implant Linux/Windows"),
                        "Implant pattern. Thu binary để phân tích, kiểm tra cron/scheduled task tương ứng.",
                        AttUserExecRefs));
                    break;
                }
            }

            // Pattern 3: removable drive (USB)
            if (info.DriveType.Equals("Removable", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(MakeFinding(
                    "RCT-REMOVABLE-" + Sanitize(target),
                    $"User {userName} đã mở file từ thiết bị USB: {Path.GetFileName(target)}",
                    Severity.Medium, "recent-files", asset,
                    BuildEvidence(info, userName, $"Drive: {info.DriveType}, Volume: {info.VolumeLabel}, Serial: 0x{info.VolumeSerial:X8}"),
                    "USB là vector phổ biến cho air-gap pivot. Đối chiếu với DeviceForensics module "
                    + "để xác định USB nào, kiểm tra USB có bị nhiễm Stuxnet-style không.",
                    AttRemovableMediaRefs));
            }

            // Pattern 4: arguments contain LOLBin pattern
            var args = info.Arguments?.ToLowerInvariant() ?? string.Empty;
            if (!string.IsNullOrEmpty(args)
                && (args.Contains("-encodedcommand", StringComparison.Ordinal)
                    || args.Contains("-enc ", StringComparison.Ordinal)
                    || args.Contains("powershell -nop", StringComparison.Ordinal)
                    || args.Contains("cmd.exe /c ", StringComparison.Ordinal)
                    || args.Contains("mshta http", StringComparison.Ordinal)
                    || args.Contains("mshta vbscript:", StringComparison.Ordinal)
                    || args.Contains("regsvr32 /s /n /u /i:http", StringComparison.Ordinal)))
            {
                findings.Add(MakeFinding(
                    "RCT-LOLBIN-LNK-" + Sanitize(target),
                    $"User {userName} có LNK với argument LOLBin: {Path.GetFileName(info.FilePath)}",
                    Severity.High, "recent-files", asset,
                    BuildEvidence(info, userName, "LNK arguments khớp pattern LOLBin loader"),
                    "LNK với argument đáng ngờ là dropper kinh điển (gửi qua email .iso → .lnk → cmd /c). "
                    + "Cô lập file LNK + phỏng vấn user về email gốc.",
                    AttLolBinRefs));
            }
        }
        return parsed;
    }

    private static void EmitJumpListSummary(
        IReadOnlyList<string> jumpListFiles, string userName, string asset, List<Finding> findings)
    {
        // Informational — JumpList parsing requires CFB library. We surface the artifact
        // count + size so DFIR can hand-process them via JLECmd / JumpListExplorer.
        var totalBytes = jumpListFiles.Sum(f => { try { return new FileInfo(f).Length; } catch { return 0L; } });
        var sample = string.Join("\n", jumpListFiles
            .Select(f => $"  {Path.GetFileName(f)} ({new FileInfo(f).Length:N0} B)")
            .Take(10));
        findings.Add(Finding.Create(
            id: "RCT-JUMPLIST-INFO-" + Sanitize(userName),
            title: $"User {userName} có {jumpListFiles.Count} JumpList file ({totalBytes:N0} B tổng cộng)",
            severity: Severity.Info,
            category: "recent-files",
            asset: asset,
            evidence: $"User: {userName}\nSố JumpList: {jumpListFiles.Count}\n"
                    + $"Mẫu (top {Math.Min(10, jumpListFiles.Count)}):\n{sample}",
            remediation: "JumpList chứa danh sách MRU per-application (Word, Excel, Notepad...). "
                       + "Để parse chi tiết: dùng JLECmd / Eric Zimmerman tool, hoặc copy thư mục "
                       + "AutomaticDestinations sang môi trường DFIR riêng."));
    }

    private static Finding MakeFinding(
        string id, string title, Severity sev, string category, string asset,
        string evidence, string remediation, IReadOnlyList<string> refs)
        => Finding.Create(id, title, sev, category, asset, evidence, remediation,
            references: null, cvss: null, attackTechniques: refs);

    private static string BuildEvidence(LnkFileParser.LnkInfo info, string userName, string reason)
    {
        var sb = new StringBuilder(512);
        sb.AppendLine($"LNK: {info.FilePath}");
        sb.AppendLine($"User: {userName}");
        sb.AppendLine($"Lý do: {reason}");
        sb.AppendLine($"Target: {info.TargetLocalPath}");
        if (!string.IsNullOrEmpty(info.WorkingDir)) { sb.AppendLine($"WorkingDir: {info.WorkingDir}"); }
        if (!string.IsNullOrEmpty(info.Arguments)) { sb.AppendLine($"Arguments: {info.Arguments}"); }
        if (!string.IsNullOrEmpty(info.Description)) { sb.AppendLine($"Description: {info.Description}"); }
        sb.AppendLine($"Drive: {info.DriveType} (Volume {info.VolumeLabel}, Serial 0x{info.VolumeSerial:X8})");
        if (info.TargetWriteTime.HasValue)
        {
            sb.AppendLine($"Target last-written: {info.TargetWriteTime:yyyy-MM-dd HH:mm:ss zzz}");
        }
        if (info.TargetAccessTime.HasValue)
        {
            sb.AppendLine($"Target last-accessed: {info.TargetAccessTime:yyyy-MM-dd HH:mm:ss zzz}");
        }
        sb.AppendLine($"Target size: {info.TargetFileSize:N0} bytes");
        return sb.ToString();
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
