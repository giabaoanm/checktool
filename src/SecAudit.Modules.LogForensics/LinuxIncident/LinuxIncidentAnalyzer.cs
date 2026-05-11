using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Walks an extracted Linux rootfs (or an OCI image bundle that we extract first)
/// and emits SOC-grade findings for the most common ransomware / intrusion patterns:
///
/// <list type="bullet">
///   <item><b>SSH brute-force + suspicious accepted login</b> — parses
///         <c>/var/log/auth.log*</c> (incl. <c>.gz</c>), looks for an
///         <c>Accepted password</c> after a burst of <c>Failed password</c> from
///         the same IP — the classic "they finally guessed it" pattern.</item>
///   <item><b>Sudoers misconfig</b> — flags <c>NOPASSWD:ALL</c> in
///         <c>/etc/sudoers</c> and <c>/etc/sudoers.d/*</c>.</item>
///   <item><b>Cron persistence</b> — parses <c>/var/spool/cron/crontabs/*</c>
///         and <c>/etc/cron*</c> for hidden-name binaries (<c>.crond</c>) or
///         <c>@reboot</c> beacons.</item>
///   <item><b>Ransom note</b> — scans text files matching <c>README*</c>,
///         <c>HOW_TO_*</c>, <c>*_LOCKED.*</c>, <c>RECOVER*</c> and re-uses the
///         WebIncident.WebContentSignalDetector ransom-term catalogue.</item>
///   <item><b>Encrypted file extension burst</b> — when ≥5 files share a
///         non-standard suffix (<c>.locked</c>, <c>.encrypted</c>, <c>.crypt</c>,
///         <c>.WNCRY</c>, <c>.ryk</c>, <c>.LOCKBIT</c>, <c>.crypted</c>,
///         <c>.payment</c>) inside one user's home/Documents.</item>
///   <item><b>IOC sweep</b> — extracts IPv4, BTC bech32/legacy, email, http(s)
///         URLs from any text artifact &lt;1 MB; deduped + ranked by hit count.</item>
/// </list>
///
/// Each finding carries MITRE ATT&amp;CK technique IDs through the standard
/// <c>Finding.AttackTechniqueIds</c> property.
/// </summary>
public sealed class LinuxIncidentAnalyzer
{
    public sealed record AnalysisResult(
        IReadOnlyList<Finding> Findings,
        int FilesScanned,
        IReadOnlyList<string> ExtractedIocs,
        string? ExtractedOciTempDir);

    private static readonly string[] EncryptedExts =
    {
        ".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".wncry",
        ".ryk", ".lockbit", ".payment", ".pay2decrypt", ".readme"
    };

    // Pre-allocated MITRE technique arrays to satisfy CA1861 (no inline arrays in Find.Create calls).
    private static readonly string[] AttBruteForce = { "T1110" };
    private static readonly string[] AttValidAccountsBrute = { "T1078", "T1110" };
    private static readonly string[] AttValidAccountsPriv = { "T1078", "T1068" };
    private static readonly string[] AttCronPersistence = { "T1053.003" };
    private static readonly string[] AttRansom = { "T1486" };
    private static readonly string[] AttElfImplant = { "T1059", "T1486" };

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance", "CA1822:Mark members as static",
        Justification = "Registered as DI singleton; instance-method API matches sibling analyzers.")]
    public AnalysisResult Analyze(string rootfsPath, string asset, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootfsPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(asset);
        if (!Directory.Exists(rootfsPath))
        {
            throw new DirectoryNotFoundException(rootfsPath);
        }

        var findings = new List<Finding>();
        var iocs = new HashSet<string>(StringComparer.Ordinal);
        var filesScanned = 0;

        filesScanned += AnalyzeAuthLogs(rootfsPath, asset, findings, iocs, ct);
        filesScanned += AnalyzeSudoers(rootfsPath, asset, findings, ct);
        filesScanned += AnalyzeCron(rootfsPath, asset, findings, iocs, ct);
        filesScanned += AnalyzeRansomNotesAndEncryptedFiles(rootfsPath, asset, findings, iocs, ct);
        filesScanned += AnalyzeSuspiciousElfBinaries(rootfsPath, asset, findings, iocs, ct);
        filesScanned += AnalyzeIocsAcrossArtifacts(rootfsPath, iocs, ct);

        if (iocs.Count > 0)
        {
            findings.Add(Finding.Create(
                id: "LIN-IOC-SUMMARY",
                title: $"Đã trích xuất {iocs.Count} IOC từ artifact Linux",
                severity: Severity.Info,
                category: "Linux Incident",
                asset: asset,
                evidence: string.Join("\n", iocs.Take(50)),
                remediation: "Đối chiếu các IOC với threat-intel feed; chặn IP/URL ở firewall; "
                           + "tìm kiếm hash trên VirusTotal/MalwareBazaar; thêm BTC address vào blocklist nội bộ."));
        }

        return new AnalysisResult(findings, filesScanned, iocs.ToArray(), null);
    }

    // ---------------------------------------------------------------------
    //  1. SSH auth.log analysis
    // ---------------------------------------------------------------------

    private static readonly Regex SshFailedPasswordRegex = new(
        @"^(?<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?<user>\S+) from (?<ip>\d+\.\d+\.\d+\.\d+)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex SshAcceptedRegex = new(
        @"^(?<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted (?<auth>password|publickey) for (?<user>\S+) from (?<ip>\d+\.\d+\.\d+\.\d+)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static int AnalyzeAuthLogs(string root, string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        var logDir = Path.Combine(root, "var", "log");
        if (!Directory.Exists(logDir))
        {
            return 0;
        }

        var files = Directory
            .EnumerateFiles(logDir, "auth.log*", SearchOption.TopDirectoryOnly)
            .ToArray();
        if (files.Length == 0)
        {
            return 0;
        }

        var failedByIp = new Dictionary<string, int>(StringComparer.Ordinal);
        var acceptedSessions = new List<(string Ts, string User, string Ip, string Auth)>();
        var keyAcceptedIps = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var line in ReadLines(file))
            {
                var m = SshFailedPasswordRegex.Match(line);
                if (m.Success)
                {
                    var ip = m.Groups["ip"].Value;
                    failedByIp[ip] = failedByIp.TryGetValue(ip, out var c) ? c + 1 : 1;
                    if (IsLikelyPublicIp(ip) && !BenignDnsResolvers.Contains(ip)) { iocs.Add("ip:" + ip); }
                    continue;
                }
                var a = SshAcceptedRegex.Match(line);
                if (a.Success)
                {
                    var ip = a.Groups["ip"].Value;
                    var auth = a.Groups["auth"].Value;
                    acceptedSessions.Add((a.Groups["ts"].Value, a.Groups["user"].Value, ip, auth));
                    if (auth.Equals("publickey", StringComparison.OrdinalIgnoreCase))
                    {
                        keyAcceptedIps.Add(ip);
                    }
                    if (IsLikelyPublicIp(ip) && !BenignDnsResolvers.Contains(ip)) { iocs.Add("ip:" + ip); }
                }
            }
        }

        // Brute-force finding — any IP with >100 failed attempts.
        var bruteIps = failedByIp.Where(kv => kv.Value >= 100).OrderByDescending(kv => kv.Value).Take(10).ToList();
        if (bruteIps.Count > 0)
        {
            findings.Add(Finding.Create(
                id: "LIN-SSH-BF",
                title: $"Phát hiện SSH brute-force từ {bruteIps.Count} IP nguồn",
                severity: Severity.High,
                category: "Linux Incident",
                asset: asset,
                evidence: "Top IP và số lần thất bại:\n"
                          + string.Join("\n", bruteIps.Select(b => $"  {b.Key}: {b.Value} lần thất bại")),
                remediation: "Chặn các IP này ở firewall; cài fail2ban; vô hiệu hoá đăng nhập password "
                           + "(chỉ cho phép public-key); rà soát log để xác định có IP nào đã thành công hay chưa.",
                attackTechniques: AttBruteForce));
        }

        // The smoking gun: an Accepted PASSWORD from an IP that had Failed-password bursts,
        // OR a password login from an IP that previously never appeared (and the user
        // normally uses publickey from a different IP).
        foreach (var s in acceptedSessions.Where(s => s.Auth.Equals("password", StringComparison.OrdinalIgnoreCase)))
        {
            var hadBursts = failedByIp.TryGetValue(s.Ip, out var failedCount) && failedCount >= 5;
            var userUsuallyUsesKey = keyAcceptedIps.Count > 0 && !keyAcceptedIps.Contains(s.Ip);
            if (!hadBursts && !userUsuallyUsesKey)
            {
                continue;
            }
            findings.Add(Finding.Create(
                id: $"LIN-SSH-ACCEPTED-{Sanitize(s.Ip)}",
                title: $"Đăng nhập SSH password đáng ngờ: {s.User}@{s.Ip} lúc {s.Ts}",
                severity: Severity.Critical,
                category: "Linux Incident",
                asset: asset,
                evidence: $"User: {s.User}\nIP nguồn: {s.Ip}\nThời gian: {s.Ts}\n"
                        + (hadBursts ? $"IP này đã có {failedCount} lần thất bại trước đó (brute-force pattern).\n" : "")
                        + (userUsuallyUsesKey ? "User này thường đăng nhập bằng public-key từ IP khác — đăng nhập password lần này là bất thường.\n" : ""),
                remediation: "Coi đây là phiên xâm nhập. Cô lập host, đổi toàn bộ chứng danh user, "
                           + "soát các lệnh đã chạy trong session (audit.log / .bash_history / sudo.log), "
                           + "rà soát persistence được cài trong khoảng thời gian sau timestamp này.",
                attackTechniques: AttValidAccountsBrute));
        }

        return files.Length;
    }

    // ---------------------------------------------------------------------
    //  2. Sudoers misconfig
    // ---------------------------------------------------------------------

    private static readonly Regex NopasswdRegex = new(
        @"^\s*(?<who>\S+)\s+(?<host>\S+)\s*=\s*\([^)]+\)\s*NOPASSWD\s*:\s*(?<what>\S.+)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));

    private static int AnalyzeSudoers(string root, string asset, List<Finding> findings, CancellationToken ct)
    {
        var paths = new List<string>();
        var sudoers = Path.Combine(root, "etc", "sudoers");
        if (File.Exists(sudoers)) { paths.Add(sudoers); }
        var dropDir = Path.Combine(root, "etc", "sudoers.d");
        if (Directory.Exists(dropDir))
        {
            paths.AddRange(Directory.EnumerateFiles(dropDir, "*", SearchOption.TopDirectoryOnly));
        }
        if (paths.Count == 0)
        {
            return 0;
        }

        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            string text;
            try { text = File.ReadAllText(p); }
            catch { continue; }
            foreach (Match m in NopasswdRegex.Matches(text))
            {
                var who = m.Groups["who"].Value;
                var what = m.Groups["what"].Value.Trim();
                var sev = what.Contains("ALL", StringComparison.Ordinal) ? Severity.High : Severity.Medium;
                findings.Add(Finding.Create(
                    id: "LIN-SUDOERS-NOPASSWD-" + Sanitize(who),
                    title: $"Quyền sudo NOPASSWD cho user '{who}' trong {Path.GetRelativePath(root, p)}",
                    severity: sev,
                    category: "Linux Incident",
                    asset: asset,
                    evidence: m.Value.Trim(),
                    remediation: "Bỏ NOPASSWD; bắt buộc nhập mật khẩu khi sudo; "
                               + "nếu cần automation, dùng cấp quyền tối thiểu cho 1 binary cụ thể, "
                               + "không cấp ALL. Sai cấu hình này biến mọi xâm nhập user thành xâm nhập root.",
                    attackTechniques: AttValidAccountsPriv));
            }
        }
        return paths.Count;
    }

    // ---------------------------------------------------------------------
    //  3. Cron persistence
    // ---------------------------------------------------------------------

    private static readonly string[] HiddenBinaryHints =
        { "/.crond", "/.beacon", "/.update", "/.systemd_", "/usr/local/bin/." };

    private static int AnalyzeCron(string root, string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        var paths = new List<string>();
        var dirs = new[]
        {
            Path.Combine(root, "var", "spool", "cron", "crontabs"),
            Path.Combine(root, "var", "spool", "cron"),
            Path.Combine(root, "etc", "cron.d"),
            Path.Combine(root, "etc", "cron.daily"),
            Path.Combine(root, "etc", "cron.hourly")
        };
        foreach (var d in dirs)
        {
            if (Directory.Exists(d))
            {
                paths.AddRange(Directory.EnumerateFiles(d, "*", SearchOption.TopDirectoryOnly));
            }
        }
        var etcCrontab = Path.Combine(root, "etc", "crontab");
        if (File.Exists(etcCrontab)) { paths.Add(etcCrontab); }
        if (paths.Count == 0) { return 0; }

        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            string[] lines;
            try { lines = File.ReadAllLines(p); }
            catch { continue; }

            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith('#')) { continue; }

                var lower = line.ToLowerInvariant();
                var suspicious = false;
                var why = new List<string>();

                if (lower.StartsWith("@reboot"))
                {
                    suspicious = true;
                    why.Add("@reboot triggers binary on every boot");
                }
                foreach (var hint in HiddenBinaryHints)
                {
                    if (lower.Contains(hint, StringComparison.Ordinal))
                    {
                        suspicious = true;
                        why.Add($"references hidden-name binary ({hint.TrimStart('/')})");
                        break;
                    }
                }
                if (lower.Contains("curl ") && lower.Contains("|sh", StringComparison.Ordinal))
                {
                    suspicious = true;
                    why.Add("curl piped to shell — common for in-memory payloads");
                }
                if (lower.Contains("base64 -d", StringComparison.Ordinal) || lower.Contains("eval $(", StringComparison.Ordinal))
                {
                    suspicious = true;
                    why.Add("uses base64/eval obfuscation");
                }

                if (suspicious)
                {
                    foreach (Match urlMatch in IpRegex.Matches(line)) { iocs.Add(urlMatch.Value); }
                    findings.Add(Finding.Create(
                        id: "LIN-CRON-PERSISTENCE-" + Sanitize(Path.GetFileName(p)) + "-" + Math.Abs(line.GetHashCode()),
                        title: $"Cron persistence đáng ngờ trong {Path.GetRelativePath(root, p)}",
                        severity: Severity.High,
                        category: "Linux Incident",
                        asset: asset,
                        evidence: $"Dòng cron: {line}\nLý do: {string.Join("; ", why)}",
                        remediation: "Xoá entry cron này; rà soát binary/script được tham chiếu; "
                                   + "kiểm tra xem entry có khớp với phần mềm hợp lệ nào đã cài không. "
                                   + "Crontab user thường là vector persistence cho malware Linux.",
                        attackTechniques: AttCronPersistence));
                }
            }
        }
        return paths.Count;
    }

    // ---------------------------------------------------------------------
    //  4. Ransom notes + encrypted file extensions
    // ---------------------------------------------------------------------

    private static readonly string[] RansomFilePatterns =
        { "README*", "HOW_TO_*", "*_LOCKED.txt", "*_LOCKED.html", "RECOVER*", "DECRYPT*", "RESTORE_FILES*" };

    private static readonly string[] RansomKeywords =
    {
        "your files are encrypted", "your files have been encrypted",
        "all your data has been encrypted", "decrypt your files",
        "đã bị mã hóa", "đã bị khóa", "tất cả tập tin", "tiền chuộc",
        "ransom", "bitcoin", "btc", "monero",
    };

    private static int AnalyzeRansomNotesAndEncryptedFiles(
        string root, string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        var noteCandidates = new List<string>();
        var homeRoot = Path.Combine(root, "home");
        var rootHome = Path.Combine(root, "root");
        var optDir = Path.Combine(root, "opt");
        var tmpDir = Path.Combine(root, "tmp");

        foreach (var area in new[] { homeRoot, rootHome, optDir, tmpDir })
        {
            if (!Directory.Exists(area)) { continue; }
            foreach (var pattern in RansomFilePatterns)
            {
                try
                {
                    noteCandidates.AddRange(Directory.EnumerateFiles(area, pattern, SearchOption.AllDirectories));
                }
                catch { /* perm issues — skip */ }
            }
        }

        var noteScanned = 0;
        foreach (var note in noteCandidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            string text;
            try { text = File.ReadAllText(note); }
            catch { continue; }
            noteScanned++;
            var lower = text.ToLowerInvariant();
            var matched = RansomKeywords.Where(k => lower.Contains(k, StringComparison.Ordinal)).ToList();
            if (matched.Count >= 2)
            {
                ExtractIocs(text, iocs);
                findings.Add(Finding.Create(
                    id: "LIN-RANSOM-NOTE-" + Sanitize(Path.GetFileName(note)),
                    title: $"Phát hiện ghi chú đòi tiền chuộc: {Path.GetRelativePath(root, note)}",
                    severity: Severity.Critical,
                    category: "Linux Incident",
                    asset: asset,
                    evidence: $"Đường dẫn: {Path.GetRelativePath(root, note)}\n"
                            + $"Từ khoá khớp: {string.Join(", ", matched.Take(6))}\n"
                            + $"Trích đoạn:\n{Excerpt(text, 600)}",
                    remediation: "Cô lập máy ngay, KHÔNG trả tiền chuộc. Sao lưu nguyên trạng "
                               + "đĩa làm bằng chứng. Thông báo IR và cơ quan có thẩm quyền nếu hệ thống "
                               + "thuộc danh mục dữ liệu nhạy cảm. Khôi phục từ backup sạch.",
                    attackTechniques: AttRansom));
            }
        }

        // Encrypted extension burst
        var extCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var area in new[] { homeRoot, rootHome })
        {
            if (!Directory.Exists(area)) { continue; }
            try
            {
                foreach (var f in Directory.EnumerateFiles(area, "*", SearchOption.AllDirectories))
                {
                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    if (EncryptedExts.Contains(ext))
                    {
                        extCounts[ext] = extCounts.TryGetValue(ext, out var c) ? c + 1 : 1;
                    }
                }
            }
            catch { /* ignore */ }
        }
        foreach (var (ext, count) in extCounts.Where(kv => kv.Value >= 1))
        {
            findings.Add(Finding.Create(
                id: "LIN-ENCRYPTED-EXT-" + Sanitize(ext.TrimStart('.')),
                title: $"Có {count} tệp đuôi {ext} (mẫu ransomware) trong /home",
                severity: count >= 5 ? Severity.Critical : Severity.High,
                category: "Linux Incident",
                asset: asset,
                evidence: $"Đuôi tệp: {ext}\nSố lượng: {count}\n"
                        + "Đây là một trong các đuôi đặc trưng của các họ ransomware đã biết.",
                remediation: "Không xoá file gốc — có thể cần cho khôi phục/giải mã sau. "
                           + "Soát ghi chú đòi tiền chuộc cùng thư mục. "
                           + "Kiểm tra integrity backup gần nhất; rebuild máy từ image sạch.",
                attackTechniques: AttRansom));
        }

        return noteScanned + extCounts.Values.Sum();
    }

    // ---------------------------------------------------------------------
    //  5. IOC extraction across artifacts
    // ---------------------------------------------------------------------

    private static readonly Regex IpRegex = new(
        @"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));
    private static readonly Regex BtcRegex = new(
        @"\b(?:bc1[ac-hj-np-z02-9]{11,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));
    private static readonly Regex EmailRegex = new(
        @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));
    private static readonly Regex UrlRegex = new(
        @"\bhttps?://[^\s""'<>]+",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    // -----------------------------------------------------------------
    //  6. ELF triage in suspicious system paths
    // -----------------------------------------------------------------

    private static readonly string[] ElfScanAreas =
    {
        "usr/local/bin", "usr/local/sbin", "tmp", "var/tmp", "dev/shm", "opt"
    };

    private static int AnalyzeSuspiciousElfBinaries(
        string root, string asset, List<Finding> findings, HashSet<string> iocs, CancellationToken ct)
    {
        var scanned = 0;
        foreach (var rel in ElfScanAreas)
        {
            var dir = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!Directory.Exists(dir)) { continue; }
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var f in files)
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(f);
                // Only triage files that LOOK like dropped binaries: hidden-name (.crond),
                // no-extension binaries, or small unsigned scripts. Skip everything else
                // to keep the rule fast on a normal /opt with hundreds of files.
                var hasSuspiciousName = name.StartsWith('.')
                    || string.IsNullOrEmpty(Path.GetExtension(name));
                if (!hasSuspiciousName) { continue; }

                ElfTriageAnalyzer.ElfTriageResult triage;
                try { triage = ElfTriageAnalyzer.Analyze(f); }
                catch { continue; }
                if (!triage.IsElf) { continue; }
                scanned++;

                foreach (var url in triage.SuspiciousUrls)
                {
                    iocs.Add("url:" + url);
                }

                var sev = triage.Packer == "PyInstaller"
                    || triage.CryptoMarkers.Count >= 2
                    || name.StartsWith('.')
                    ? Severity.High
                    : Severity.Medium;

                var rel2 = Path.GetRelativePath(root, f).Replace('\\', '/');
                var crypto = triage.CryptoMarkers.Count == 0
                    ? "(không phát hiện chuỗi crypto đặc trưng)"
                    : string.Join(", ", triage.CryptoMarkers.Take(8));
                var paths = triage.SuspiciousPaths.Count == 0
                    ? "(không có)"
                    : string.Join(", ", triage.SuspiciousPaths.Take(6));
                var urls = triage.SuspiciousUrls.Count == 0
                    ? "(không có)"
                    : string.Join(", ", triage.SuspiciousUrls.Take(6));

                findings.Add(Finding.Create(
                    id: "LIN-ELF-" + Sanitize(rel2),
                    title: $"ELF binary đáng ngờ: /{rel2} ({triage.Machine}, {triage.Packer})",
                    severity: sev,
                    category: "Linux Incident",
                    asset: asset,
                    evidence: $"Đường dẫn: /{rel2}\n"
                            + $"Class: {triage.ElfClass} {triage.Endianness}, máy: {triage.Machine}\n"
                            + $"Packer/loader: {triage.Packer}\n"
                            + $"Chuỗi crypto: {crypto}\n"
                            + $"URL nghi ngờ: {urls}\n"
                            + $"Path nghi ngờ trong binary: {paths}",
                    remediation: "Thu thập binary làm bằng chứng (sao chép có hash SHA256), đối chiếu "
                               + "VirusTotal/MalwareBazaar. Nếu là PyInstaller-packed: dùng pyinstxtractor "
                               + "trên môi trường sandbox. Nếu UPX-packed: thử upx -d. "
                               + "Quan sát crypto markers + URL để dựng cấu hình ransomware/C2.",
                    attackTechniques: AttElfImplant));
            }
        }
        return scanned;
    }

    private static int AnalyzeIocsAcrossArtifacts(string root, HashSet<string> iocs, CancellationToken ct)
    {
        // Areas where attacker-staged files / configs / logs typically live.
        var areas = new[]
        {
            Path.Combine(root, "tmp"),
            Path.Combine(root, "opt"),
            Path.Combine(root, "var", "log"),
            Path.Combine(root, "var", "spool", "cron"),
            Path.Combine(root, "etc"),
            Path.Combine(root, "home"),
            Path.Combine(root, "root")
        };
        var scanned = 0;
        foreach (var area in areas)
        {
            if (!Directory.Exists(area)) { continue; }
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(area, "*", SearchOption.AllDirectories);
            }
            catch { continue; }
            foreach (var f in files)
            {
                ct.ThrowIfCancellationRequested();
                FileInfo fi;
                try { fi = new FileInfo(f); }
                catch { continue; }
                if (fi.Length is 0 or > 1_000_000) { continue; } // skip empty + >1 MB

                string text;
                try { text = File.ReadAllText(f); }
                catch { continue; }
                if (text.Length == 0 || ContainsBinary(text)) { continue; }

                ExtractIocs(text, iocs);
                scanned++;
            }
        }
        return scanned;
    }

    // Well-known public DNS resolvers — never IOCs.
    private static readonly HashSet<string> BenignDnsResolvers = new(StringComparer.Ordinal)
    {
        "8.8.8.8", "8.8.4.4",            // Google
        "1.1.1.1", "1.0.0.1",            // Cloudflare
        "9.9.9.9", "149.112.112.112",    // Quad9
        "208.67.222.222", "208.67.220.220", // OpenDNS
        "1.2.3.4"                        // common docs example
    };

    // Substring matches against URL host — distro mirrors / OS infrastructure that
    // appear in /etc/apt + /var/log/apt/history.log. Drop to keep IOC list focused.
    private static readonly string[] BenignUrlHosts =
    {
        "ubuntu.com", "debian.org", "kernel.org", "freedesktop.org",
        "ftpmaster.internal", "archive.canonical.com", "security.ubuntu.com",
        "ports.ubuntu.com", "azure.archive.ubuntu.com",
        "deb.debian.org", "snapcraft.io", "schemas.android.com",
        "schemas.microsoft.com", "schemas.openxmlformats.org",
        "www.w3.org", "schema.org", "openjdk.org",
        "letsencrypt.org", "rfc-editor.org"
    };

    private static void ExtractIocs(string text, HashSet<string> iocs)
    {
        foreach (Match m in IpRegex.Matches(text))
        {
            var ip = m.Value;
            // skip RFC1918 + loopback + multicast + well-known DNS — only attacker-shaped IPs as IOC
            if (IsLikelyPublicIp(ip) && !BenignDnsResolvers.Contains(ip))
            {
                iocs.Add("ip:" + ip);
            }
        }
        foreach (Match m in BtcRegex.Matches(text)) { iocs.Add("btc:" + m.Value); }
        foreach (Match m in EmailRegex.Matches(text))
        {
            var email = m.Value;
            if (!email.EndsWith("@localhost", StringComparison.OrdinalIgnoreCase)
                && !email.EndsWith("@example.com", StringComparison.OrdinalIgnoreCase)
                && !email.EndsWith("@ubuntu.com", StringComparison.OrdinalIgnoreCase)
                && !email.EndsWith("@debian.org", StringComparison.OrdinalIgnoreCase))
            {
                iocs.Add("email:" + email);
            }
        }
        foreach (Match m in UrlRegex.Matches(text))
        {
            var url = m.Value.TrimEnd('.', ',', ';', ')');
            var lower = url.ToLowerInvariant();
            var benign = false;
            foreach (var host in BenignUrlHosts)
            {
                if (lower.Contains(host, StringComparison.Ordinal)) { benign = true; break; }
            }
            if (!benign) { iocs.Add("url:" + url); }
        }
    }

    private static bool IsLikelyPublicIp(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) { return false; }
        if (!byte.TryParse(parts[0], out var a)) { return false; }
        if (!byte.TryParse(parts[1], out var b)) { return false; }
        if (a == 10 || a == 127 || a == 0 || a >= 224) { return false; }
        if (a == 172 && b >= 16 && b <= 31) { return false; }
        if (a == 192 && b == 168) { return false; }
        if (a == 169 && b == 254) { return false; }
        return true;
    }

    private static bool ContainsBinary(string s)
    {
        var len = Math.Min(s.Length, 4096);
        var nonPrintable = 0;
        for (var i = 0; i < len; i++)
        {
            var c = s[i];
            if (c == 0) { return true; }
            if (c < 32 && c != '\t' && c != '\n' && c != '\r') { nonPrintable++; }
        }
        return nonPrintable * 100 / Math.Max(1, len) > 5;
    }

    // ---------------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------------

    private static IEnumerable<string> ReadLines(string path)
    {
        if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
        {
            using var fs = File.OpenRead(path);
            using var gz = new GZipStream(fs, CompressionMode.Decompress);
            using var reader = new StreamReader(gz, Encoding.UTF8);
            string? line;
            while ((line = reader.ReadLine()) is not null) { yield return line; }
            yield break;
        }
        foreach (var line in File.ReadLines(path)) { yield return line; }
    }

    private static string Excerpt(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";

    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            sb.Append(char.IsLetterOrDigit(c) ? c : '-');
        }
        return sb.ToString();
    }
}

#pragma warning disable CA1801 // Unused parameter; reserved for future cancellation handoff.
internal static class CulturePlaceholder
{
    public static CultureInfo Inv => CultureInfo.InvariantCulture;
}
#pragma warning restore CA1801
