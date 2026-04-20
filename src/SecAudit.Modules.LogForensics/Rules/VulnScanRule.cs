using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects vulnerability / reconnaissance scanning against HTTP endpoints by combining
/// two heuristics:
///   (a) User-Agent contains a known scanner fingerprint (Nessus, Nikto, sqlmap, nmap,
///       masscan, OpenVAS, Acunetix, ZAP, nuclei, wpscan, dirbuster, gobuster, ffuf).
///   (b) A single client IP hits &gt; <see cref="UriThreshold"/> distinct URIs within
///       <see cref="WindowSeconds"/> — classic URL fuzzing / directory brute-force.
/// Either signal is enough to raise a High finding.
/// </summary>
public sealed class VulnScanRule : IDetectionRule
{
    public string Id => "FOR-VULNSCAN";
    public string Name => "Quét lỗ hổng / dò URL (Vulnerability scan)";

    private const int UriThreshold = 50;
    private const int WindowSeconds = 300;

    private static readonly string[] ScannerAgents =
    {
        "nessus", "nikto", "sqlmap", "nmap", "masscan", "openvas", "acunetix",
        "zaproxy", "owasp zap", "nuclei", "wpscan", "dirbuster", "gobuster",
        "ffuf", "feroxbuster", "arachni", "qualys", "burpcollaborator", "wfuzz"
    };

    private static readonly string[] ReferencesArr =
    {
        "MITRE ATT&CK T1595 — Active Scanning",
        "MITRE ATT&CK T1190 — Exploit Public-Facing Application"
    };

    private readonly Dictionary<string, (DateTimeOffset first, HashSet<string> uris, string sampleUa)> _byIp =
        new(StringComparer.Ordinal);
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "http.request") { return; }
        var ip = record.GetField("IpAddress");
        if (string.IsNullOrWhiteSpace(ip)) { return; }

        var ua = record.GetField("UserAgent") ?? string.Empty;
        var uri = record.GetField("Uri") ?? "/";

        // (a) Scanner UA signal — emit immediately, once per IP.
        foreach (var agent in ScannerAgents)
        {
            if (ua.Contains(agent, StringComparison.OrdinalIgnoreCase))
            {
                var key = "UA:" + ip;
                if (_emitted.Add(key))
                {
                    ctx.Emit(Finding.Create(
                        id: $"{Id}-UA-{Math.Abs(ip.GetHashCode()):X8}",
                        title: $"Công cụ quét lỗ hổng phát hiện qua User-Agent từ {ip}",
                        severity: Severity.High,
                        category: "log-forensics.vuln-scan",
                        asset: $"ip:{ip}",
                        evidence: $"[{record.SourceFile}:{record.SourceOffset}] UA=\"{ua}\" matched \"{agent}\"\n"
                            + $"URI sample: {uri}\nRaw: {record.RawLine}",
                        remediation: $"Chặn/ratelimit IP {ip} tại WAF/nginx. Kiểm tra xem có yêu cầu nào đã trả 200/500"
                            + " (có thể là khai thác thực sự). Lưu bằng chứng log để báo cáo lên CERT.",
                        references: ReferencesArr));
                }
                break;
            }
        }

        // (b) URL-fan-out signal.
        if (!_byIp.TryGetValue(ip, out var st))
        {
            st = (record.Timestamp, new HashSet<string>(StringComparer.Ordinal), ua);
            _byIp[ip] = st;
        }
        if (record.Timestamp - st.first > TimeSpan.FromSeconds(WindowSeconds))
        {
            // reset window
            st = (record.Timestamp, new HashSet<string>(StringComparer.Ordinal), ua);
        }
        st.uris.Add(uri);
        _byIp[ip] = st;

        if (st.uris.Count >= UriThreshold)
        {
            var key = "FAN:" + ip;
            if (_emitted.Add(key))
            {
                ctx.Emit(Finding.Create(
                    id: $"{Id}-FAN-{Math.Abs(ip.GetHashCode()):X8}",
                    title: $"Dò URL hàng loạt từ {ip} — {st.uris.Count} URI trong {WindowSeconds}s",
                    severity: Severity.High,
                    category: "log-forensics.vuln-scan",
                    asset: $"ip:{ip}",
                    evidence: $"IP {ip} đã truy cập {st.uris.Count} URI khác nhau trong {WindowSeconds}s.\n"
                        + "URI mẫu (5):\n  " + string.Join("\n  ", st.uris.Take(5))
                        + $"\nUA: {st.sampleUa}",
                    remediation: $"Rate-limit IP {ip} tại WAF. Kiểm tra 404/403 ratio để xác định scan tool;"
                        + " block bằng fail2ban hoặc nginx limit_req nếu cần.",
                    references: ReferencesArr));
            }
        }
    }

    public void Flush(ForensicsContext ctx) { }

    public void Reset()
    {
        _byIp.Clear();
        _emitted.Clear();
    }
}
