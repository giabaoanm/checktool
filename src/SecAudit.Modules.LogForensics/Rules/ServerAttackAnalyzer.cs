using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Correlates recent live-server telemetry into operator-friendly attack findings.
/// This is intentionally deterministic and source-agnostic so it can consume Windows
/// events, Sysmon events, and IIS/Nginx/Apache records from the existing parsers.
/// </summary>
public sealed class ServerAttackAnalyzer
{
    private const int BruteForceThreshold = 10;
    private const int PasswordSprayUserThreshold = 5;
    private const int HttpFanoutThreshold = 50;
    private const int HttpExploitProbeThreshold = 5;

    private readonly Dictionary<string, LoginBucket> _failedByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, LoginBucket> _failedByUser = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HttpBucket> _httpByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<LoginSuccess> _successes = new();
    private readonly List<Finding> _directFindings = new();
    private readonly HashSet<string> _directIds = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] References =
    {
        "MITRE ATT&CK T1110 - Brute Force",
        "MITRE ATT&CK T1190 - Exploit Public-Facing Application",
        "MITRE ATT&CK T1078 - Valid Accounts",
        "MITRE ATT&CK T1003.001 - LSASS Memory"
    };

    public void Observe(LogRecord record, string asset)
    {
        switch (record.EventKind)
        {
            case "logon.failed":
                ObserveFailedLogon(record);
                break;
            case "logon.success":
            case "logon.explicit":
                ObserveSuccessfulLogon(record);
                break;
            case "http.request":
                ObserveHttpRequest(record);
                break;
            case "process.created":
            case "sysmon.process":
                ObserveProcessCreate(record, asset);
                break;
            case "sysmon.processaccess":
                ObserveProcessAccess(record, asset);
                break;
            case "log.cleared":
                EmitDirect(
                    "SRV-LOG-CLEARED-" + StableHash(record.SourceFile + record.SourceOffset),
                    "Event log was cleared on server",
                    Severity.Critical,
                    "server-attack.evidence-tampering",
                    asset,
                    Evidence(record),
                    "Investigate who cleared the log, preserve remaining logs, and review adjacent authentication/process events.");
                break;
            case "service.installed":
                ObserveServiceInstalled(record, asset);
                break;
            case "task.created":
                EmitPersistence(record, asset, "New scheduled task created", "server-attack.persistence.task");
                break;
            case "account.created":
                EmitPersistence(record, asset, "New local/domain account created", "server-attack.account-change");
                break;
            case "group.memberadded":
                EmitPersistence(record, asset, "Account added to privileged group", "server-attack.privilege-change");
                break;
        }
    }

    public IReadOnlyList<Finding> BuildFindings(string asset)
    {
        var findings = new List<Finding>(_directFindings);

        foreach (var (ip, bucket) in _failedByIp)
        {
            if (bucket.Count < BruteForceThreshold)
            {
                continue;
            }

            var severity = bucket.Count >= BruteForceThreshold * 3
                           || bucket.Users.Count >= PasswordSprayUserThreshold
                           || IsPublicIp(ip)
                ? Severity.Critical
                : Severity.High;
            var spray = bucket.Users.Count >= PasswordSprayUserThreshold
                ? $" Password-spray pattern: {bucket.Users.Count} accounts targeted."
                : string.Empty;
            findings.Add(Finding.Create(
                id: "SRV-BRUTE-IP-" + StableHash(ip),
                title: $"Possible online password attack from {ip}",
                severity: severity,
                category: "server-attack.brute-force",
                asset: "ip:" + ip,
                evidence:
                    $"{bucket.Count} failed logons from {ip} between {FormatUtc(bucket.First)} and {FormatUtc(bucket.Last)} UTC."
                    + $"{spray}\nUsers: {string.Join(", ", bucket.Users.Take(12))}\n"
                    + "Samples:\n" + string.Join("\n", bucket.Samples.TakeLast(5)),
                remediation:
                    $"Block or rate-limit {ip}, inspect any successful logon from the same source, and reset targeted accounts if compromise is suspected.",
                references: References));
        }

        foreach (var (user, bucket) in _failedByUser)
        {
            if (bucket.Count < BruteForceThreshold)
            {
                continue;
            }

            findings.Add(Finding.Create(
                id: "SRV-BRUTE-USER-" + StableHash(user),
                title: $"Account {user} is under password attack",
                severity: bucket.Sources.Any(IsPublicIp) ? Severity.Critical : Severity.High,
                category: "server-attack.brute-force",
                asset: "user:" + user,
                evidence:
                    $"{bucket.Count} failed logons against {user} between {FormatUtc(bucket.First)} and {FormatUtc(bucket.Last)} UTC.\n"
                    + $"Sources: {string.Join(", ", bucket.Sources.Take(12))}\n"
                    + "Samples:\n" + string.Join("\n", bucket.Samples.TakeLast(5)),
                remediation:
                    $"Lock or rotate {user} if not expected; review VPN/RDP/IIS exposure and check for a later successful logon.",
                references: References));
        }

        foreach (var success in _successes)
        {
            if (string.IsNullOrWhiteSpace(success.Ip) || !_failedByIp.TryGetValue(success.Ip, out var bucket))
            {
                continue;
            }
            if (bucket.Count < BruteForceThreshold || success.Timestamp < bucket.First)
            {
                continue;
            }

            findings.Add(Finding.Create(
                id: "SRV-BRUTE-SUCCESS-" + StableHash(success.Ip + "|" + success.User),
                title: $"Successful logon after repeated failures from {success.Ip}",
                severity: Severity.Critical,
                category: "server-attack.compromise-suspected",
                asset: $"user:{success.User}",
                evidence:
                    $"Source {success.Ip} had {bucket.Count} failed logons, then a successful logon for {success.User} at {FormatUtc(success.Timestamp)} UTC.\n"
                    + Evidence(success.Record),
                remediation:
                    "Treat this as possible account compromise: isolate session if active, reset credential, review lateral movement, and preserve logs.",
                references: References));
        }

        foreach (var (ip, bucket) in _httpByIp)
        {
            bool scanner = !string.IsNullOrWhiteSpace(bucket.ScannerUserAgent);
            bool fanout = bucket.Uris.Count >= HttpFanoutThreshold;
            bool exploit = bucket.ExploitProbeCount >= HttpExploitProbeThreshold;
            if (!scanner && !fanout && !exploit)
            {
                continue;
            }

            var severity = exploit || scanner && fanout ? Severity.Critical : Severity.High;
            var reasons = new List<string>();
            if (scanner) { reasons.Add("scanner User-Agent: " + bucket.ScannerUserAgent); }
            if (fanout) { reasons.Add($"{bucket.Uris.Count} distinct URLs"); }
            if (exploit) { reasons.Add($"{bucket.ExploitProbeCount} exploit-like probes"); }

            findings.Add(Finding.Create(
                id: "SRV-WEB-SCAN-" + StableHash(ip),
                title: $"Possible web attack or vulnerability scan from {ip}",
                severity: severity,
                category: "server-attack.web-scan",
                asset: "ip:" + ip,
                evidence:
                    $"{string.Join("; ", reasons)} between {FormatUtc(bucket.First)} and {FormatUtc(bucket.Last)} UTC.\n"
                    + "URI samples:\n" + string.Join("\n", bucket.Samples.TakeLast(8)),
                remediation:
                    $"Block or rate-limit {ip} at firewall/WAF, review HTTP 200/500 responses for these probes, and inspect the web root for new files.",
                references: References));
        }

        return findings
            .GroupBy(f => f.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void ObserveFailedLogon(LogRecord record)
    {
        var ip = NormalizeIp(GetAny(record, "IpAddress", "SourceIp", "c-ip"));
        var user = NormalizeUser(GetAny(record, "TargetUserName", "User", "AccountName"));

        if (!string.IsNullOrWhiteSpace(ip))
        {
            var b = GetBucket(_failedByIp, ip!, record.Timestamp);
            b.Count++;
            b.Last = Max(b.Last, record.Timestamp);
            if (!string.IsNullOrWhiteSpace(user)) { b.Users.Add(user!); }
            b.Samples.Add(Evidence(record));
        }

        if (!string.IsNullOrWhiteSpace(user))
        {
            var b = GetBucket(_failedByUser, user!, record.Timestamp);
            b.Count++;
            b.Last = Max(b.Last, record.Timestamp);
            if (!string.IsNullOrWhiteSpace(ip)) { b.Sources.Add(ip!); }
            b.Samples.Add(Evidence(record));
        }
    }

    private void ObserveSuccessfulLogon(LogRecord record)
    {
        var ip = NormalizeIp(GetAny(record, "IpAddress", "SourceIp", "c-ip"));
        var user = NormalizeUser(GetAny(record, "TargetUserName", "User", "AccountName"));
        if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(user))
        {
            return;
        }
        _successes.Add(new LoginSuccess(ip!, user!, record.Timestamp, record));
    }

    private void ObserveHttpRequest(LogRecord record)
    {
        var ip = NormalizeIp(GetAny(record, "IpAddress", "SourceIp", "c-ip"));
        if (string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        var bucket = GetHttpBucket(ip!, record.Timestamp);
        bucket.Last = Max(bucket.Last, record.Timestamp);

        var uri = GetAny(record, "Uri", "cs-uri-stem") ?? "/";
        var userAgent = GetAny(record, "UserAgent", "cs(User-Agent)") ?? string.Empty;
        bucket.Uris.Add(uri);
        if (IsScannerUserAgent(userAgent))
        {
            bucket.ScannerUserAgent ??= userAgent;
        }
        if (IsExploitProbe(uri))
        {
            bucket.ExploitProbeCount++;
        }
        bucket.Samples.Add($"[{record.SourceFile}:{record.SourceOffset}] {uri} UA=\"{userAgent}\"");
    }

    private void ObserveProcessCreate(LogRecord record, string asset)
    {
        var image = GetAny(record, "Image", "NewProcessName", "ProcessName") ?? string.Empty;
        var parent = GetAny(record, "ParentImage", "ParentProcessName") ?? string.Empty;
        var commandLine = GetAny(record, "CommandLine", "ProcessCommandLine") ?? record.RawLine;
        var childName = Path.GetFileName(image);
        var parentName = Path.GetFileName(parent);

        if (IsWebServerProcess(parentName) && (IsShellOrLolbin(childName) || IsHighRiskCommand(commandLine)))
        {
            EmitDirect(
                "SRV-WEBSHELL-PROC-" + StableHash(parent + "|" + image + "|" + commandLine),
                $"Web server process spawned suspicious child: {childName}",
                Severity.Critical,
                "server-attack.webshell",
                asset,
                Evidence(record),
                "Assume possible web shell or RCE: isolate the server, inspect web root/upload folders, and preserve process/log evidence.");
        }
        else if (IsHighRiskCommand(commandLine))
        {
            EmitDirect(
                "SRV-HIGHRISK-CMD-" + StableHash(image + "|" + commandLine),
                $"High-risk command line observed: {childName}",
                Severity.High,
                "server-attack.suspicious-process",
                asset,
                Evidence(record),
                "Verify the command owner and parent process. If not administrative activity, isolate and collect memory/process evidence.");
        }
    }

    private void ObserveProcessAccess(LogRecord record, string asset)
    {
        var target = GetAny(record, "TargetImage") ?? string.Empty;
        if (!target.EndsWith("\\lsass.exe", StringComparison.OrdinalIgnoreCase)
            && !target.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var access = (GetAny(record, "GrantedAccess") ?? string.Empty).ToLowerInvariant();
        if (!IsDangerousLsassMask(access))
        {
            return;
        }

        var source = GetAny(record, "SourceImage") ?? "(unknown)";
        EmitDirect(
            "SRV-LSASS-" + StableHash(source + "|" + access),
            $"Suspicious LSASS memory access by {Path.GetFileName(source)}",
            Severity.Critical,
            "server-attack.credential-access",
            asset,
            Evidence(record),
            "Possible credential dumping. Isolate host, identify source process, and rotate privileged credentials used on this server.");
    }

    private void EmitPersistence(LogRecord record, string asset, string title, string category)
    {
        EmitDirect(
            "SRV-PERSIST-" + StableHash(category + "|" + record.SourceFile + "|" + record.SourceOffset),
            title,
            Severity.High,
            category,
            asset,
            Evidence(record),
            "Verify change owner and timestamp. If unauthorized, disable the service/task/account and review adjacent logon/process events.");
    }

    private void ObserveServiceInstalled(LogRecord record, string asset)
    {
        var serviceName = GetAny(record, "ServiceName", "Service Name", "Service") ??
                          ExtractRenderedField(record, "Service Name") ??
                          "(unknown)";
        var imagePath = GetAny(record, "ImagePath", "ServiceFileName", "Service File Name", "Service File Name") ??
                        ExtractRenderedField(record, "Service File Name") ??
                        ExtractRenderedField(record, "ImagePath") ??
                        string.Empty;
        var startType = GetAny(record, "StartType", "Service Start Type") ??
                        ExtractRenderedField(record, "Service Start Type") ??
                        string.Empty;
        var serviceType = GetAny(record, "ServiceType", "Service Type") ??
                          ExtractRenderedField(record, "Service Type") ??
                          string.Empty;

        if (IsKnownBenignServiceInstall(serviceName, imagePath, serviceType))
        {
            return;
        }

        var severity = ClassifyServiceInstallSeverity(imagePath, startType);
        var title = severity >= Severity.High
            ? $"Suspicious service installed: {serviceName}"
            : $"New service installed: {serviceName}";
        var remediation = severity >= Severity.High
            ? "Treat as possible persistence: preserve the service config, copy the binary for analysis, then disable/remove only after evidence is saved."
            : "Review whether the service install matches a known software/driver change. If authorized, record it in the baseline; otherwise inspect adjacent logon/process events.";

        var evidence = Evidence(record);
        if (!string.IsNullOrWhiteSpace(imagePath)
            && !evidence.Contains(imagePath, StringComparison.OrdinalIgnoreCase))
        {
            evidence += "\nParsed ImagePath: " + imagePath;
        }

        EmitDirect(
            "SRV-PERSIST-" + StableHash("service|" + serviceName + "|" + imagePath),
            title,
            severity,
            "server-attack.persistence.service",
            asset,
            evidence,
            remediation);
    }

    private static Severity ClassifyServiceInstallSeverity(string imagePath, string startType)
    {
        var lower = imagePath.Replace('/', '\\').ToLowerInvariant();
        var autoStart = startType.Contains("auto", StringComparison.OrdinalIgnoreCase)
                        || startType.Contains("boot", StringComparison.OrdinalIgnoreCase)
                        || startType.Contains("system", StringComparison.OrdinalIgnoreCase);

        if (ContainsAny(lower,
                @"\appdata\local\temp\",
                @"\appdata\roaming\",
                @"\users\public\",
                @"\windows\temp\",
                @"\downloads\",
                "powershell -enc",
                "powershell.exe -enc",
                "-encodedcommand",
                "regsvr32 /s /u /i:http",
                "rundll32.exe javascript:"))
        {
            return Severity.High;
        }

        return autoStart ? Severity.High : Severity.Medium;
    }

    private static bool IsKnownBenignServiceInstall(string serviceName, string imagePath, string serviceType)
    {
        var lowerName = serviceName.Trim().ToLowerInvariant();
        var lowerPath = imagePath.Replace('/', '\\').ToLowerInvariant();
        var lowerType = serviceType.ToLowerInvariant();

        return lowerName.Equals("iomap", StringComparison.Ordinal)
               && lowerPath.EndsWith(@"\windows\system32\drivers\iomap64.sys", StringComparison.Ordinal)
               && (lowerType.Length == 0 || lowerType.Contains("kernel", StringComparison.Ordinal));
    }

    private static string? ExtractRenderedField(LogRecord record, string label)
    {
        var raw = record.RawLine;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        using var reader = new StringReader(raw);
        string? line;
        var prefix = label + ":";
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = trimmed[prefix.Length..].Trim();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        return null;
    }

    private void EmitDirect(
        string id,
        string title,
        Severity severity,
        string category,
        string asset,
        string evidence,
        string remediation)
    {
        if (!_directIds.Add(id))
        {
            return;
        }

        _directFindings.Add(Finding.Create(
            id: id,
            title: title,
            severity: severity,
            category: category,
            asset: asset,
            evidence: evidence,
            remediation: remediation,
            references: References));
    }

    private static LoginBucket GetBucket(Dictionary<string, LoginBucket> map, string key, DateTimeOffset ts)
    {
        if (!map.TryGetValue(key, out var b))
        {
            b = new LoginBucket(ts);
            map[key] = b;
        }
        return b;
    }

    private HttpBucket GetHttpBucket(string ip, DateTimeOffset ts)
    {
        if (!_httpByIp.TryGetValue(ip, out var b))
        {
            b = new HttpBucket(ts);
            _httpByIp[ip] = b;
        }
        return b;
    }

    private static string? GetAny(LogRecord record, params string[] names)
    {
        foreach (var name in names)
        {
            var value = record.GetField(name);
            if (!string.IsNullOrWhiteSpace(value) && value != "-")
            {
                return value;
            }
        }
        return null;
    }

    private static string? NormalizeIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw is "-" or "::1" or "127.0.0.1")
        {
            return null;
        }
        return raw.Trim();
    }

    private static string? NormalizeUser(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw == "-")
        {
            return null;
        }
        var user = raw.Trim();
        if (user.EndsWith('$') || user.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
            || user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        return user;
    }

    private static bool IsScannerUserAgent(string userAgent)
    {
        return ContainsAny(userAgent,
            "nessus", "nikto", "sqlmap", "nmap", "masscan", "openvas",
            "acunetix", "zaproxy", "owasp zap", "nuclei", "wpscan",
            "dirbuster", "gobuster", "ffuf", "feroxbuster", "burp");
    }

    private static bool IsExploitProbe(string uri)
    {
        return ContainsAny(uri,
            "/.env", "/.git/", "wp-login", "wp-admin", "phpmyadmin",
            "/cgi-bin/", "/actuator", "jndi:", "../", "%2e%2e",
            "etc/passwd", "cmd=", "powershell", "wget", "curl",
            "union+select", "union%20select", "%27%20or%20", "' or ",
            "<script", "%3cscript", "base64", "eval(", "webshell", "shell.aspx",
            "cmd.aspx", "upload.aspx");
    }

    private static bool IsWebServerProcess(string name)
    {
        return ContainsAny(name, "w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe",
            "tomcat", "java.exe", "node.exe", "dotnet.exe");
    }

    private static bool IsShellOrLolbin(string name)
    {
        return ContainsAny(name, "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
            "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "wmic.exe", "curl.exe", "wget.exe");
    }

    private static bool IsHighRiskCommand(string command)
    {
        return ContainsAny(command, " -enc ", "encodedcommand", "frombase64string",
            "downloadstring", "invoke-webrequest", "invoke-restmethod", " iwr ",
            "certutil", "urlcache", "vssadmin delete", "wbadmin delete",
            "wevtutil cl", "mimikatz", "sekurlsa::", "procdump", "comsvcs.dll",
            "minidump", "reg save hklm\\sam", "reg save hklm\\security");
    }

    private static bool IsDangerousLsassMask(string access)
    {
        return ContainsAny(access, "0x1010", "0x1410", "0x1438", "0x143a",
            "0x1fffff", "0x1f0fff", "0x1f1fff", "0x101010");
    }

    private static bool IsPublicIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr))
        {
            return false;
        }
        var b = addr.GetAddressBytes();
        if (b.Length != 4) { return false; }
        if (b[0] == 10 || b[0] == 127) { return false; }
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) { return false; }
        if (b[0] == 192 && b[1] == 168) { return false; }
        if (b[0] == 169 && b[1] == 254) { return false; }
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) { return false; }
        if (b[0] >= 224) { return false; }
        return true;
    }

    private static bool ContainsAny(string haystack, params string[] needles) =>
        needles.Any(n => haystack.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static string Evidence(LogRecord record) =>
        $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u} {record.RawLine}";

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;

    private static string FormatUtc(DateTimeOffset ts) =>
        ts.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    private static string StableHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..12];
    }

    private sealed class LoginBucket
    {
        public LoginBucket(DateTimeOffset first)
        {
            First = first;
            Last = first;
        }

        public int Count { get; set; }
        public DateTimeOffset First { get; }
        public DateTimeOffset Last { get; set; }
        public HashSet<string> Users { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Samples { get; } = new();
    }

    private sealed class HttpBucket
    {
        public HttpBucket(DateTimeOffset first)
        {
            First = first;
            Last = first;
        }

        public DateTimeOffset First { get; }
        public DateTimeOffset Last { get; set; }
        public HashSet<string> Uris { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int ExploitProbeCount { get; set; }
        public string? ScannerUserAgent { get; set; }
        public List<string> Samples { get; } = new();
    }

    private sealed record LoginSuccess(string Ip, string User, DateTimeOffset Timestamp, LogRecord Record);
}
