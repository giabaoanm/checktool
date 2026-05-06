using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.WebIncident;

public sealed partial class WebServerEvidenceAnalyzer
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static readonly string[] LogExtensions =
    {
        ".log", ".txt", ".access", ".error"
    };

    private static readonly string[] WebRootExtensions =
    {
        ".php", ".phtml", ".phar", ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx",
        ".js", ".html", ".htm", ".config", ".htaccess", ".env", ".inc", ".bak", ".old", ".sql", ".zip"
    };

    private static readonly string[] ScannerAgents =
    {
        "sqlmap", "nikto", "nuclei", "zgrab", "masscan", "acunetix", "nessus", "dirbuster",
        "gobuster", "ffuf", "wpscan", "netsparker", "burp", "python-requests"
    };

    [SuppressMessage(
        "Performance",
        "CA1822:Mark members as static",
        Justification = "Registered as an injectable analyzer; keeping instance API matches other module services.")]
    public async Task<WebServerEvidenceAnalysis> AnalyzeAsync(
        WebIncidentSettings settings,
        string evidenceRoot,
        string asset,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(asset);

        var findings = new List<Finding>();
        var manifest = new List<WebIncidentEvidenceFile>();
        var timeline = new List<WebAttackTimelineEvent>();
        var webrootManifest = new List<WebRootFileRecord>();
        var suspiciousFiles = new List<WebRootFileRecord>();

        var serverEvidencePath = settings.ServerEvidencePath.Trim();
        var importResult = await PrepareServerEvidenceAsync(
            serverEvidencePath,
            evidenceRoot,
            manifest,
            cancellationToken).ConfigureAwait(false);
        var workingServerEvidencePath = importResult.WorkingPath;
        if (importResult.SkippedRiskyFiles.Count > 0)
        {
            webrootManifest.AddRange(importResult.SkippedRiskyFiles);
            suspiciousFiles.AddRange(importResult.SkippedRiskyFiles);
        }

        if (!string.IsNullOrWhiteSpace(workingServerEvidencePath) && Directory.Exists(workingServerEvidencePath))
        {
            var logFiles = EnumerateEvidenceFiles(
                workingServerEvidencePath,
                settings.MaxServerEvidenceFiles,
                LogExtensions);

            foreach (var logFile in logFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();
                timeline.AddRange(await ParseLogFileAsync(logFile, workingServerEvidencePath, cancellationToken)
                    .ConfigureAwait(false));
            }
        }

        AddTimelineFindings(timeline, asset, findings);
        if (timeline.Count > 0)
        {
            manifest.Add(await WriteTextAsync(
                evidenceRoot,
                "web-attack-timeline.csv",
                "web-timeline",
                FormatTimelineCsv(timeline),
                cancellationToken).ConfigureAwait(false));
            manifest.Add(await WriteTextAsync(
                evidenceRoot,
                "web-attack-timeline.json",
                "web-timeline",
                JsonSerializer.Serialize(timeline, JsonOptions),
                cancellationToken).ConfigureAwait(false));
        }

        var webRootPath = ResolveWebRootPath(settings, workingServerEvidencePath);
        if (!string.IsNullOrWhiteSpace(webRootPath) && Directory.Exists(webRootPath))
        {
            foreach (var file in EnumerateEvidenceFiles(
                         webRootPath,
                         settings.MaxServerEvidenceFiles,
                         WebRootExtensions))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var record = await BuildWebRootRecordAsync(file, webRootPath, cancellationToken)
                    .ConfigureAwait(false);
                webrootManifest.Add(record);

                var suspicious = await ClassifySuspiciousFileAsync(file, record, cancellationToken)
                    .ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(suspicious))
                {
                    suspiciousFiles.Add(record with { Classification = suspicious });
                }
            }

            manifest.Add(await WriteTextAsync(
                evidenceRoot,
                "webroot-manifest.csv",
                "webroot-manifest",
                FormatWebRootManifestCsv(webrootManifest),
                cancellationToken).ConfigureAwait(false));
        }

        AddWebRootFindings(suspiciousFiles, webRootPath, asset, findings);

        var baselineManifestPath = settings.BaselineManifestPath.Trim();
        if (!string.IsNullOrWhiteSpace(baselineManifestPath)
            && File.Exists(baselineManifestPath)
            && webrootManifest.Count > 0)
        {
            var baseline = await LoadBaselineManifestAsync(baselineManifestPath, cancellationToken)
                .ConfigureAwait(false);
            AddBaselineFindings(baseline, webrootManifest, baselineManifestPath, asset, findings);
        }

        if (timeline.Count == 0 && webrootManifest.Count == 0 && string.IsNullOrWhiteSpace(serverEvidencePath))
        {
            return new WebServerEvidenceAnalysis(null, Array.Empty<WebIncidentEvidenceFile>(), Array.Empty<Finding>());
        }

        var summary = new WebServerEvidenceSummary(
            SourcePath: string.IsNullOrWhiteSpace(serverEvidencePath) ? null : serverEvidencePath,
            WebRootPath: string.IsNullOrWhiteSpace(webRootPath) ? null : webRootPath,
            BaselineManifestPath: string.IsNullOrWhiteSpace(baselineManifestPath) ? null : baselineManifestPath,
            Timeline: timeline
                .OrderBy(e => e.Timestamp ?? DateTimeOffset.MinValue)
                .ThenBy(e => e.SourceFile, StringComparer.OrdinalIgnoreCase)
                .Take(1000)
                .ToArray(),
            WebRootManifest: webrootManifest.ToArray(),
            SuspiciousFiles: suspiciousFiles.ToArray());

        manifest.Add(await WriteTextAsync(
            evidenceRoot,
            "server-evidence-summary.json",
            "server-evidence",
            JsonSerializer.Serialize(summary, JsonOptions),
            cancellationToken).ConfigureAwait(false));

        return new WebServerEvidenceAnalysis(summary, manifest, findings);
    }

    private static async Task<ServerEvidenceImportResult> PrepareServerEvidenceAsync(
        string sourcePath,
        string evidenceRoot,
        List<WebIncidentEvidenceFile> manifest,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            return new ServerEvidenceImportResult(null, Array.Empty<WebRootFileRecord>());
        }

        if (Directory.Exists(sourcePath))
        {
            return new ServerEvidenceImportResult(sourcePath, Array.Empty<WebRootFileRecord>());
        }

        if (File.Exists(sourcePath) && string.Equals(Path.GetExtension(sourcePath), ".zip", StringComparison.OrdinalIgnoreCase))
        {
            var extractRoot = Path.Combine(evidenceRoot, "server-evidence-import");
            Directory.CreateDirectory(extractRoot);
            var skipped = await ExtractZipEvidenceSafelyAsync(
                sourcePath,
                extractRoot,
                cancellationToken).ConfigureAwait(false);
            manifest.Add(await WriteBytesEvidenceAsync(
                evidenceRoot,
                "server-evidence-source.zip.sha256.txt",
                "server-evidence-source",
                Encoding.UTF8.GetBytes(Sha256Hex(await File.ReadAllBytesAsync(sourcePath, cancellationToken)
                    .ConfigureAwait(false))),
                cancellationToken).ConfigureAwait(false));
            if (skipped.Count > 0)
            {
                manifest.Add(await WriteTextAsync(
                    evidenceRoot,
                    "server-evidence-skipped-risky-files.csv",
                    "server-evidence-skipped",
                    FormatWebRootManifestCsv(skipped),
                    cancellationToken).ConfigureAwait(false));
            }
            return new ServerEvidenceImportResult(extractRoot, skipped);
        }

        return new ServerEvidenceImportResult(null, Array.Empty<WebRootFileRecord>());
    }

    private static async Task<IReadOnlyList<WebRootFileRecord>> ExtractZipEvidenceSafelyAsync(
        string zipPath,
        string extractRoot,
        CancellationToken cancellationToken)
    {
        var skipped = new List<WebRootFileRecord>();
        var rootFullPath = Path.GetFullPath(extractRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;

        using var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(entry.Name))
            {
                continue;
            }

            var relative = NormalizeZipEntryName(entry.FullName);
            if (relative is null)
            {
                skipped.Add(new WebRootFileRecord(
                    entry.FullName,
                    entry.Length,
                    entry.LastWriteTime.UtcDateTime,
                    await Sha256ZipEntryAsync(entry, cancellationToken).ConfigureAwait(false),
                    "Unsafe ZIP path skipped"));
                continue;
            }

            if (IsRiskyZipEvidenceEntry(relative))
            {
                skipped.Add(new WebRootFileRecord(
                    relative,
                    entry.Length,
                    entry.LastWriteTime.UtcDateTime,
                    await Sha256ZipEntryAsync(entry, cancellationToken).ConfigureAwait(false),
                    "Executable file skipped from ZIP evidence"));
                continue;
            }

            var destination = Path.GetFullPath(Path.Combine(
                extractRoot,
                relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!destination.StartsWith(rootFullPath, StringComparison.OrdinalIgnoreCase))
            {
                skipped.Add(new WebRootFileRecord(
                    relative,
                    entry.Length,
                    entry.LastWriteTime.UtcDateTime,
                    await Sha256ZipEntryAsync(entry, cancellationToken).ConfigureAwait(false),
                    "Unsafe ZIP path skipped"));
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            entry.ExtractToFile(destination, overwrite: true);
        }

        return skipped;
    }

    private static string ResolveWebRootPath(WebIncidentSettings settings, string? workingServerEvidencePath)
    {
        if (!string.IsNullOrWhiteSpace(settings.WebRootPath) && Directory.Exists(settings.WebRootPath))
        {
            return settings.WebRootPath.Trim();
        }

        if (string.IsNullOrWhiteSpace(workingServerEvidencePath) || !Directory.Exists(workingServerEvidencePath))
        {
            return string.Empty;
        }

        var candidates = Directory.EnumerateDirectories(workingServerEvidencePath, "*", SearchOption.AllDirectories)
            .Where(d =>
            {
                var name = Path.GetFileName(d);
                return name.Equals("wwwroot", StringComparison.OrdinalIgnoreCase)
                       || name.Equals("public_html", StringComparison.OrdinalIgnoreCase)
                       || name.Equals("htdocs", StringComparison.OrdinalIgnoreCase)
                       || name.Equals("www", StringComparison.OrdinalIgnoreCase)
                       || name.Equals("public", StringComparison.OrdinalIgnoreCase);
            })
            .Take(1)
            .ToArray();
        return candidates.Length == 0 ? string.Empty : candidates[0];
    }

    private static string[] EnumerateEvidenceFiles(
        string root,
        int maxFiles,
        IReadOnlyList<string> extensions)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Where(p => extensions.Contains(Path.GetExtension(p), StringComparer.OrdinalIgnoreCase)
                            || string.Equals(Path.GetFileName(p), ".htaccess", StringComparison.OrdinalIgnoreCase)
                            || string.Equals(Path.GetFileName(p), ".env", StringComparison.OrdinalIgnoreCase))
                .Take(Math.Clamp(maxFiles, 100, 100000))
                .ToArray();
        }
        catch (UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
    }

    private static async Task<IReadOnlyList<WebAttackTimelineEvent>> ParseLogFileAsync(
        string path,
        string root,
        CancellationToken cancellationToken)
    {
        var events = new List<WebAttackTimelineEvent>();
        var fields = Array.Empty<string>();
        var relative = Path.GetRelativePath(root, path);
        var lineNumber = 0;

        await foreach (var line in ReadLinesAsync(path, cancellationToken).ConfigureAwait(false))
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
            {
                fields = line[8..].Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                continue;
            }
            if (line.StartsWith('#'))
            {
                continue;
            }

            var parsed = fields.Length > 0
                ? TryParseIis(line, fields, relative)
                : TryParseCombined(line, relative);
            if (parsed is null)
            {
                parsed = FallbackParse(line, relative);
            }

            var rule = ClassifyRequest(parsed);
            if (rule is null)
            {
                continue;
            }

            events.Add(parsed with
            {
                Rule = rule,
                Raw = TrimForEvidence(lineNumber.ToString(CultureInfo.InvariantCulture) + ": " + parsed.Raw, 600)
            });
        }

        return events;
    }

    private static WebAttackTimelineEvent? TryParseCombined(string line, string sourceFile)
    {
        var match = CombinedLogRegex().Match(line);
        if (!match.Success)
        {
            return null;
        }

        var request = match.Groups["request"].Value;
        var parts = request.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var method = parts.Length > 0 ? parts[0] : string.Empty;
        var path = parts.Length > 1 ? parts[1] : request;
        return new WebAttackTimelineEvent(
            TryParseApacheTimestamp(match.Groups["time"].Value),
            match.Groups["ip"].Value,
            method,
            path,
            int.TryParse(match.Groups["status"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var status)
                ? status
                : null,
            match.Groups["ua"].Value,
            string.Empty,
            sourceFile,
            line);
    }

    private static WebAttackTimelineEvent? TryParseIis(string line, IReadOnlyList<string> fields, string sourceFile)
    {
        var values = SplitW3c(line);
        if (values.Length < fields.Count)
        {
            return null;
        }

        string Value(string field)
        {
            var idx = IndexOfField(fields, field);
            return idx >= 0 && idx < values.Length ? values[idx] : string.Empty;
        }

        var date = Value("date");
        var time = Value("time");
        DateTimeOffset? timestamp = null;
        if (DateTimeOffset.TryParse(
                date + " " + time + " +00:00",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var parsedTime))
        {
            timestamp = parsedTime;
        }

        var stem = Value("cs-uri-stem");
        var query = Value("cs-uri-query");
        var path = string.IsNullOrWhiteSpace(query) || query == "-"
            ? stem
            : stem + "?" + query;
        return new WebAttackTimelineEvent(
            timestamp,
            Value("c-ip"),
            Value("cs-method"),
            path,
            int.TryParse(Value("sc-status"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var status)
                ? status
                : null,
            Uri.UnescapeDataString(Value("cs(User-Agent)").Replace('+', ' ')),
            string.Empty,
            sourceFile,
            line);
    }

    private static WebAttackTimelineEvent FallbackParse(string line, string sourceFile)
    {
        var ip = IpRegex().Match(line).Value;
        var request = RequestRegex().Match(line);
        return new WebAttackTimelineEvent(
            null,
            ip,
            request.Success ? request.Groups["method"].Value : string.Empty,
            request.Success ? request.Groups["path"].Value : line,
            null,
            string.Empty,
            string.Empty,
            sourceFile,
            line);
    }

    private static string? ClassifyRequest(WebAttackTimelineEvent e)
    {
        var text = (e.Path + " " + e.UserAgent + " " + e.Raw).ToLowerInvariant();

        if (ContainsAny(text, "sqlmap", "union%20select", "union+select", "union select",
                "information_schema", "sleep(", "benchmark(", "waitfor delay", "or%201=1"))
        {
            return "SQL injection";
        }
        if (ContainsAny(text, "../", "%2e%2e", "..%2f", "%252e%252e", "/etc/passwd", "boot.ini", "win.ini"))
        {
            return "Path traversal / LFI";
        }
        if (ContainsAny(text, "php://", "file://", "expect://", "data://", "=http://", "=https://"))
        {
            return "RFI/LFI wrapper";
        }
        if (ContainsAny(text, ";cat", "%3bcat", "|cat", "%7ccat", "cmd.exe", "powershell",
                "wget%20", "curl%20", "/bin/sh", "bash%20-c"))
        {
            return "Command injection";
        }
        if (ContainsAny(text, "/uploads/", "/upload/", "/files/", "/cache/", "/tmp/")
            && ContainsAny(text, ".php", ".phtml", ".phar", ".aspx", ".jsp"))
        {
            return "Possible webshell access";
        }
        if (ContainsAny(text, "wp-login.php", "xmlrpc.php", "/administrator/index.php", "/admin/login"))
        {
            return "Admin login target";
        }
        if (ScannerAgents.Any(a => text.Contains(a, StringComparison.OrdinalIgnoreCase)))
        {
            return "Scanner user-agent";
        }
        if (e.StatusCode >= 500)
        {
            return "HTTP 5xx";
        }
        return null;
    }

    private static void AddTimelineFindings(
        IReadOnlyList<WebAttackTimelineEvent> timeline,
        string asset,
        List<Finding> findings)
    {
        if (timeline.Count == 0)
        {
            return;
        }

        AddRuleFinding(timeline, "Possible webshell access", "WEB-LOG-WEBSHELL", Severity.Critical,
            "Log web có truy cập file nghi webshell",
            "Cô lập webroot, thu file bị gọi trong log, kiểm tra tiến trình web server và rà soát tài khoản quản trị CMS/hosting sau thời điểm request.");
        AddRuleFinding(timeline, "Command injection", "WEB-LOG-CMD-INJECTION", Severity.Critical,
            "Log web có dấu hiệu command injection",
            "Tạm ngắt public traffic hoặc bật WAF rule chặn payload, thu log ứng dụng, rà soát process con của web server và vá endpoint liên quan.");
        AddRuleFinding(timeline, "SQL injection", "WEB-LOG-SQLI", Severity.High,
            "Log web có dấu hiệu SQL injection",
            "Xác định endpoint/parameter, kiểm tra database log và tài khoản DB, vá truy vấn tham số hóa và rà soát dữ liệu bị trích xuất.");
        AddRuleFinding(timeline, "Path traversal / LFI", "WEB-LOG-LFI", Severity.High,
            "Log web có dấu hiệu path traversal hoặc LFI",
            "Kiểm tra endpoint đọc file, log ứng dụng và quyền file; vá kiểm soát đường dẫn và thu bằng chứng file nhạy cảm bị truy cập nếu có.");
        AddRuleFinding(timeline, "RFI/LFI wrapper", "WEB-LOG-RFI", Severity.High,
            "Log web có dấu hiệu RFI/LFI wrapper",
            "Kiểm tra cấu hình PHP allow_url_include/include path, rà webshell mới tạo và vá endpoint include file.");
        AddRuleFinding(timeline, "Scanner user-agent", "WEB-LOG-SCANNER", Severity.Medium,
            "Log web có dấu hiệu công cụ dò quét tự động",
            "Chặn hoặc rate-limit IP nguồn nếu còn diễn ra, sau đó kiểm tra các request sau scan có dẫn tới upload/webshell hay lỗi 5xx hay không.");

        var adminByIp = timeline
            .Where(e => e.Rule == "Admin login target")
            .GroupBy(e => e.SourceIp)
            .Where(g => !string.IsNullOrWhiteSpace(g.Key) && g.Count() >= 20)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToArray();
        if (adminByIp.Length > 0)
        {
            findings.Add(Finding.Create(
                "WEB-LOG-ADMIN-BRUTEFORCE",
                "Log web có dấu hiệu brute force vào trang quản trị",
                Severity.High,
                "web-incident.server-log",
                asset,
                string.Join("\n", adminByIp.Select(g => $"{g.Key}: {g.Count()} request tới admin/login endpoint")),
                "Khóa/rate-limit IP nguồn, kiểm tra đăng nhập thành công sau chuỗi thử sai, đổi mật khẩu tài khoản quản trị và bật MFA nếu có."));
        }

        var dosByMinute = timeline
            .Where(e => e.Timestamp.HasValue)
            .GroupBy(e => new
            {
                e.SourceIp,
                Bucket = new DateTimeOffset(
                    e.Timestamp!.Value.Year,
                    e.Timestamp.Value.Month,
                    e.Timestamp.Value.Day,
                    e.Timestamp.Value.Hour,
                    e.Timestamp.Value.Minute,
                    0,
                    e.Timestamp.Value.Offset)
            })
            .Where(g => !string.IsNullOrWhiteSpace(g.Key.SourceIp) && g.Count() >= 300)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToArray();
        if (dosByMinute.Length > 0)
        {
            findings.Add(Finding.Create(
                "WEB-LOG-DOS-SPIKE",
                "Log web có lưu lượng bất thường theo phút",
                Severity.High,
                "web-incident.dos",
                asset,
                string.Join("\n", dosByMinute.Select(g =>
                    $"{g.Key.Bucket:O} {g.Key.SourceIp}: {g.Count()} request/phút")),
                "Đối chiếu CDN/WAF/firewall log, áp dụng rate-limit hoặc chặn nguồn tấn công và kiểm tra endpoint bị flood."));
        }

        void AddRuleFinding(
            IReadOnlyList<WebAttackTimelineEvent> source,
            string rule,
            string id,
            Severity severity,
            string title,
            string remediation)
        {
            var matches = source.Where(e => e.Rule == rule).Take(20).ToArray();
            if (matches.Length == 0)
            {
                return;
            }
            findings.Add(Finding.Create(
                id,
                title,
                severity,
                "web-incident.server-log",
                asset,
                string.Join("\n", matches.Select(FormatTimelineEvidence)),
                remediation));
        }
    }

    private static async Task<WebRootFileRecord> BuildWebRootRecordAsync(
        string file,
        string root,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(file);
        var bytes = await File.ReadAllBytesAsync(file, cancellationToken).ConfigureAwait(false);
        return new WebRootFileRecord(
            Path.GetRelativePath(root, file).Replace('\\', '/'),
            info.Length,
            info.LastWriteTimeUtc,
            Sha256Hex(bytes),
            ClassifyByPath(file));
    }

    private static async Task<string?> ClassifySuspiciousFileAsync(
        string file,
        WebRootFileRecord record,
        CancellationToken cancellationToken)
    {
        var lowerPath = record.RelativePath.ToLowerInvariant();
        var ext = Path.GetExtension(file).ToLowerInvariant();

        if (ContainsAny(lowerPath, "/uploads/", "/upload/", "/cache/", "/tmp/", "/images/")
            && ext is ".php" or ".phtml" or ".phar" or ".aspx" or ".jsp")
        {
            return "Executable file in upload/cache/tmp path";
        }
        if (Regex.IsMatch(lowerPath, @"\.(jpg|jpeg|png|gif|ico|pdf)\.(php|phtml|aspx|jsp)$", RegexOptions.IgnoreCase))
        {
            return "Double-extension executable file";
        }
        if (record.SizeBytes > 2_000_000)
        {
            return null;
        }

        string text;
        try
        {
            text = await File.ReadAllTextAsync(file, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is DecoderFallbackException or IOException or UnauthorizedAccessException)
        {
            return null;
        }

        var lower = text.ToLowerInvariant();
        if (ext is ".php" or ".phtml" or ".phar" or ".inc")
        {
            var score = 0;
            if (ContainsAny(lower, "eval(", "assert(", "preg_replace", "create_function(")) { score += 2; }
            if (ContainsAny(lower, "base64_decode", "gzinflate", "str_rot13", "chr(", "pack(")) { score += 2; }
            if (ContainsAny(lower, "shell_exec", "passthru", "system(", "proc_open", "popen(")) { score += 2; }
            if (ContainsAny(lower, "$_post", "$_get", "$_request", "$_cookie")) { score++; }
            if (LongBase64Regex().IsMatch(text)) { score += 2; }
            if (score >= 4) { return "PHP webshell-like code"; }
        }
        if (ext is ".aspx" or ".ashx" or ".asmx" or ".asp")
        {
            if (ContainsAny(lower, "processstartinfo", "cmd.exe", "powershell", "eval(", "request["))
            {
                return "ASP.NET/ASP webshell-like code";
            }
        }
        if (ext is ".jsp" or ".jspx")
        {
            if (ContainsAny(lower, "runtime.getruntime().exec", "processbuilder", "request.getparameter", "cmd.exe"))
            {
                return "JSP webshell-like code";
            }
        }
        if (ContainsAny(lower, "your files are encrypted", "decrypt your files", "hacked by", "defaced by"))
        {
            return "Deface/ransom note content";
        }
        if (Path.GetFileName(file).Equals(".env", StringComparison.OrdinalIgnoreCase)
            || lowerPath.EndsWith(".sql", StringComparison.OrdinalIgnoreCase)
            || lowerPath.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)
            || lowerPath.EndsWith(".old", StringComparison.OrdinalIgnoreCase))
        {
            return "Sensitive backup/config file in webroot";
        }

        return null;
    }

    private static void AddWebRootFindings(
        IReadOnlyList<WebRootFileRecord> suspiciousFiles,
        string webRootPath,
        string asset,
        List<Finding> findings)
    {
        if (suspiciousFiles.Count == 0)
        {
            return;
        }

        var webshell = suspiciousFiles
            .Where(f => ContainsAny(f.Classification, "webshell", "Executable file", "Double-extension"))
            .Take(20)
            .ToArray();
        if (webshell.Length > 0)
        {
            findings.Add(Finding.Create(
                "WEBROOT-WEBSHELL-SUSPECT",
                "Webroot có file nghi webshell hoặc file thực thi đặt sai vị trí",
                Severity.Critical,
                "web-incident.webroot",
                asset,
                FormatWebRootEvidence(webRootPath, webshell),
                "Không xóa ngay file nghi vấn; sao lưu bằng chứng, đối chiếu log request gọi file đó, kiểm tra user tạo file và rà toàn bộ tài khoản quản trị trước khi khôi phục bản sạch."));
        }

        var sensitive = suspiciousFiles
            .Where(f => ContainsAny(f.Classification, "Sensitive", "Deface", "ransom"))
            .Take(20)
            .ToArray();
        if (sensitive.Length > 0)
        {
            findings.Add(Finding.Create(
                "WEBROOT-SENSITIVE-OR-DEFACE",
                "Webroot có file nhạy cảm hoặc nội dung deface/ransom",
                Severity.High,
                "web-incident.webroot",
                asset,
                FormatWebRootEvidence(webRootPath, sensitive),
                "Di chuyển file nhạy cảm ra ngoài webroot, kiểm tra lịch sử triển khai và rà soát dấu hiệu deface/ransom trong các template/index."));
        }
    }

    private static async Task<IReadOnlyDictionary<string, string>> LoadBaselineManifestAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        await foreach (var line in ReadLinesAsync(path, cancellationToken).ConfigureAwait(false))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("RelativePath,", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var parts = SplitCsv(line);
            if (parts.Count >= 4)
            {
                result[parts[0].Replace('\\', '/')] = parts[3];
            }
        }
        return result;
    }

    private static void AddBaselineFindings(
        IReadOnlyDictionary<string, string> baseline,
        IReadOnlyList<WebRootFileRecord> current,
        string baselineManifestPath,
        string asset,
        List<Finding> findings)
    {
        if (baseline.Count == 0)
        {
            return;
        }

        var currentByPath = current.ToDictionary(f => f.RelativePath, StringComparer.OrdinalIgnoreCase);
        var changed = current
            .Where(f => baseline.TryGetValue(f.RelativePath, out var sha)
                        && !string.Equals(sha, f.Sha256, StringComparison.OrdinalIgnoreCase))
            .Take(30)
            .ToArray();
        var added = current
            .Where(f => !baseline.ContainsKey(f.RelativePath))
            .Take(30)
            .ToArray();
        var missing = baseline.Keys
            .Where(path => !currentByPath.ContainsKey(path))
            .Take(30)
            .ToArray();

        if (changed.Length > 0 || added.Length > 0 || missing.Length > 0)
        {
            var evidence = new StringBuilder();
            evidence.AppendLine("Baseline: " + baselineManifestPath);
            foreach (var f in changed)
            {
                evidence.AppendLine("CHANGED " + f.RelativePath + " sha256=" + f.Sha256);
            }
            foreach (var f in added)
            {
                evidence.AppendLine("NEW " + f.RelativePath + " sha256=" + f.Sha256);
            }
            foreach (var path in missing)
            {
                evidence.AppendLine("MISSING " + path);
            }

            findings.Add(Finding.Create(
                "WEBROOT-BASELINE-DRIFT",
                "Webroot khác baseline sạch",
                Severity.High,
                "web-incident.webroot",
                asset,
                evidence.ToString(),
                "So sánh từng file với bản triển khai sạch, ưu tiên index/template/plugin mới sửa; nếu không hợp lệ, khôi phục từ backup sạch và xoay vòng thông tin xác thực quản trị."));
        }
    }

    private static string FormatTimelineCsv(IReadOnlyList<WebAttackTimelineEvent> timeline)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Timestamp,SourceIp,Method,Path,StatusCode,Rule,SourceFile,UserAgent,Raw");
        foreach (var e in timeline.OrderBy(e => e.Timestamp ?? DateTimeOffset.MinValue).Take(5000))
        {
            sb.AppendLine(string.Join(",", new[]
            {
                Csv(e.Timestamp?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty),
                Csv(e.SourceIp),
                Csv(e.Method),
                Csv(e.Path),
                Csv(e.StatusCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
                Csv(e.Rule),
                Csv(e.SourceFile),
                Csv(e.UserAgent),
                Csv(e.Raw)
            }));
        }
        return sb.ToString();
    }

    private static string FormatWebRootManifestCsv(IReadOnlyList<WebRootFileRecord> records)
    {
        var sb = new StringBuilder();
        sb.AppendLine("RelativePath,SizeBytes,LastWriteUtc,Sha256,Classification");
        foreach (var r in records.OrderBy(r => r.RelativePath, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine(string.Join(",", new[]
            {
                Csv(r.RelativePath),
                Csv(r.SizeBytes.ToString(CultureInfo.InvariantCulture)),
                Csv(r.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture)),
                Csv(r.Sha256),
                Csv(r.Classification)
            }));
        }
        return sb.ToString();
    }

    private static string FormatTimelineEvidence(WebAttackTimelineEvent e)
        => $"{e.Timestamp?.ToString("O", CultureInfo.InvariantCulture) ?? "no-time"} {e.SourceIp} "
           + $"{e.Method} {e.Path} status={e.StatusCode?.ToString(CultureInfo.InvariantCulture) ?? "?"} "
           + $"rule={e.Rule} file={e.SourceFile}";

    private static string FormatWebRootEvidence(string webRootPath, IReadOnlyList<WebRootFileRecord> files)
    {
        var sb = new StringBuilder();
        sb.AppendLine("WebRoot: " + webRootPath);
        foreach (var f in files)
        {
            sb.AppendLine($"{f.Classification}: {f.RelativePath} size={f.SizeBytes} sha256={f.Sha256} modified={f.LastWriteUtc:O}");
        }
        return sb.ToString();
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(
        string path,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        while (!reader.EndOfStream)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is not null)
            {
                yield return line;
            }
        }
    }

    private static DateTimeOffset? TryParseApacheTimestamp(string value)
    {
        return DateTimeOffset.TryParseExact(
            value,
            "dd/MMM/yyyy:HH:mm:ss zzz",
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out var parsed)
            ? parsed
            : null;
    }

    private static string[] SplitW3c(string line)
        => line.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray();

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        result.Add(current.ToString());
        return result;
    }

    private static int IndexOfField(IReadOnlyList<string> fields, string field)
    {
        for (var i = 0; i < fields.Count; i++)
        {
            if (string.Equals(fields[i], field, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }
        return -1;
    }

    private static string Csv(string value)
        => "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static string ClassifyByPath(string path)
    {
        var lower = path.Replace('\\', '/').ToLowerInvariant();
        if (ContainsAny(lower, "/uploads/", "/upload/", "/cache/", "/tmp/"))
        {
            return "upload/cache/tmp";
        }
        if (Path.GetFileName(path).Equals(".env", StringComparison.OrdinalIgnoreCase)
            || lower.EndsWith(".sql", StringComparison.OrdinalIgnoreCase)
            || lower.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)
            || lower.EndsWith(".old", StringComparison.OrdinalIgnoreCase))
        {
            return "sensitive";
        }
        return "webroot";
    }

    private static string? NormalizeZipEntryName(string entryName)
    {
        var normalized = entryName.Replace('\\', '/').TrimStart('/');
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.Contains("..", StringComparison.Ordinal)
            || Path.IsPathRooted(normalized))
        {
            return null;
        }
        return normalized;
    }

    private static bool IsRiskyZipEvidenceEntry(string relativePath)
    {
        var ext = Path.GetExtension(relativePath).ToLowerInvariant();
        return ext is ".php" or ".phtml" or ".phar" or ".asp" or ".aspx" or ".ashx" or ".asmx"
            or ".jsp" or ".jspx" or ".exe" or ".dll" or ".scr" or ".com" or ".ps1" or ".bat"
            or ".cmd" or ".vbs" or ".js" or ".jse" or ".hta" or ".zip" or ".7z" or ".rar";
    }

    private static async Task<string> Sha256ZipEntryAsync(
        ZipArchiveEntry entry,
        CancellationToken cancellationToken)
    {
        await using var stream = entry.Open();
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }

    private static async Task<WebIncidentEvidenceFile> WriteTextAsync(
        string root,
        string name,
        string kind,
        string content,
        CancellationToken cancellationToken)
        => await WriteBytesEvidenceAsync(root, name, kind, Encoding.UTF8.GetBytes(content), cancellationToken)
            .ConfigureAwait(false);

    private static async Task<WebIncidentEvidenceFile> WriteBytesEvidenceAsync(
        string root,
        string name,
        string kind,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(root, name);
        await File.WriteAllBytesAsync(path, bytes, cancellationToken).ConfigureAwait(false);
        return new WebIncidentEvidenceFile(name, path, kind, bytes.LongLength, Sha256Hex(bytes), DateTimeOffset.UtcNow);
    }

    private static string Sha256Hex(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes));

    private static string TrimForEvidence(string value, int max)
        => value.Length <= max ? value : value[..max] + "...";

    private static bool ContainsAny(string value, params string[] terms)
        => terms.Any(t => value.Contains(t, StringComparison.OrdinalIgnoreCase));

    [GeneratedRegex("^(?<ip>\\S+)\\s+\\S+\\s+\\S+\\s+\\[(?<time>[^\\]]+)\\]\\s+\"(?<request>[^\"]*)\"\\s+(?<status>\\d{3}|-)\\s+\\S+(?:\\s+\"[^\"]*\"\\s+\"(?<ua>[^\"]*)\")?.*$")]
    private static partial Regex CombinedLogRegex();

    [GeneratedRegex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")]
    private static partial Regex IpRegex();

    [GeneratedRegex("\"(?<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+(?<path>[^\\s\"]+)", RegexOptions.IgnoreCase)]
    private static partial Regex RequestRegex();

    [GeneratedRegex("[A-Za-z0-9+/]{160,}={0,2}")]
    private static partial Regex LongBase64Regex();

    private sealed record ServerEvidenceImportResult(
        string? WorkingPath,
        IReadOnlyList<WebRootFileRecord> SkippedRiskyFiles);
}

public sealed record WebServerEvidenceAnalysis(
    WebServerEvidenceSummary? Summary,
    IReadOnlyList<WebIncidentEvidenceFile> Manifest,
    IReadOnlyList<Finding> Findings);
