using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.WebIncident;

public sealed class WebIncidentEvidenceCollector
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly WebServerEvidenceAnalyzer _serverEvidenceAnalyzer;
    private readonly ILogger<WebIncidentEvidenceCollector> _logger;

    public WebIncidentEvidenceCollector(
        WebServerEvidenceAnalyzer serverEvidenceAnalyzer,
        ILogger<WebIncidentEvidenceCollector> logger)
    {
        _serverEvidenceAnalyzer = serverEvidenceAnalyzer;
        _logger = logger;
    }

    public async Task<WebIncidentResult> CollectAsync(
        string target,
        WebIncidentSettings settings,
        IProgress<WebIncidentProgress> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(progress);

        var started = DateTimeOffset.UtcNow;
        var liveProbe = settings.EnableLiveWebProbe;
        if (liveProbe && string.IsNullOrWhiteSpace(target))
        {
            throw new ArgumentException("Live web probe cần domain hoặc URL hợp lệ.", nameof(target));
        }
        var displayTarget = string.IsNullOrWhiteSpace(target)
            ? "Evidence-only website incident"
            : target.Trim();
        Uri? normalized = null;
        if (!string.IsNullOrWhiteSpace(target))
        {
            if (liveProbe)
            {
                normalized = NormalizeTarget(target);
            }
            else
            {
                try
                {
                    normalized = NormalizeTarget(target);
                }
                catch (ArgumentException)
                {
                    normalized = null;
                }
            }
        }
        var asset = normalized?.Host ?? "web-evidence";
        var normalizedUrl = normalized?.ToString() ?? "(evidence-only)";
        var sessionId = "web-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
            + "-" + SafeFileName(asset);
        var root = PrepareEvidenceRoot(settings.EvidenceRoot, sessionId);
        var manifest = new List<WebIncidentEvidenceFile>();
        var findings = new List<Finding>();
        var http = new List<WebHttpObservation>();
        WebDnsObservation? dns = null;
        WebTlsObservation? tls = null;
        WebContentSignals? signals = null;
        var liveResources = new List<WebLiveResourceObservation>();
        WebServerEvidenceSummary? serverEvidence = null;
        byte[]? finalBody = null;
        Uri? finalUri = normalized;

        progress.Report(new WebIncidentProgress(sessionId, "Tạo thư mục bằng chứng", 5));
        manifest.Add(await WriteTextAsync(root, "incident-playbook.md", "playbook",
            BuildPlaybook(displayTarget, liveProbe), cancellationToken).ConfigureAwait(false));

        if (liveProbe && normalized is not null)
        {
            progress.Report(new WebIncidentProgress(sessionId, "Thu thập DNS", 15));
            dns = await CollectDnsAsync(normalized.Host, cancellationToken).ConfigureAwait(false);
            manifest.Add(await WriteTextAsync(root, "dns.txt", "dns",
                FormatDns(dns), cancellationToken).ConfigureAwait(false));
            if (dns.Error is not null)
            {
                findings.Add(Finding.Create(
                    "WEB-DNS-FAILED",
                    "Không phân giải được DNS của website",
                    Severity.High,
                    "web-incident.availability",
                    normalized.Host,
                    $"Host: {normalized.Host}\nError: {dns.Error}\nEvidence: dns.txt",
                    "Kiểm tra bản ghi DNS tại registrar/DNS hosting, đối chiếu thay đổi gần nhất, khóa tài khoản quản trị DNS và khôi phục bản ghi sạch."));
            }

        if (string.Equals(normalized.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            progress.Report(new WebIncidentProgress(sessionId, "Thu thập chứng thư TLS", 30));
            tls = await CollectTlsAsync(normalized.Host, normalized.Port > 0 ? normalized.Port : 443, cancellationToken)
                .ConfigureAwait(false);
            manifest.Add(await WriteTextAsync(root, "tls.txt", "tls",
                FormatTls(tls), cancellationToken).ConfigureAwait(false));
            AddTlsFindings(normalized, tls, findings);
        }

        progress.Report(new WebIncidentProgress(sessionId,
            settings.CaptureHttpBody ? "Thu thập HTTP/HTTPS và nội dung" : "Thu thập HTTP/HTTPS metadata",
            50));
        try
        {
            var httpResult = await CollectHttpAsync(normalized, settings, root, manifest, cancellationToken)
                .ConfigureAwait(false);
            http.AddRange(httpResult.Observations);
            finalBody = httpResult.FinalBody;
            finalUri = httpResult.FinalUri;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            _logger.LogWarning(ex, "HTTP collection failed for {Target}", normalized);
            http.Add(new WebHttpObservation(
                normalized.ToString(),
                0,
                null,
                string.Empty,
                0,
                null,
                string.Empty,
                0,
                string.Empty,
                ex.Message,
                EmptyHeaders()));
        }

        manifest.Add(await WriteTextAsync(root, "http-observations.json", "http",
            JsonSerializer.Serialize(http, JsonOptions), cancellationToken).ConfigureAwait(false));
        AddHttpFindings(normalized, http, findings, settings.SlowResponseThresholdMs);
        AddHttpHeaderFindings(normalized, http, findings);

        if (!settings.SafeLiveContentAnalysis && !settings.CaptureHttpBody)
        {
            findings.Add(Finding.Create(
                "WEB-CONTENT-CAPTURE-DISABLED",
                "Chưa thu nội dung trang trong chế độ an toàn với antivirus",
                Severity.Info,
                "web-incident.evidence",
                normalized.Host,
                "SecAudit chỉ thu DNS/TLS/HTTP headers/status. BodySha256 và rule deface/ransom theo nội dung không chạy trong chế độ này.",
                "Nếu cần xác minh deface theo nội dung HTML, bật tùy chọn 'Thu nội dung HTML' trong GUI hoặc dùng --web-capture-body trong CLI. Chỉ bật khi antivirus đã cho phép công cụ chạy."));
        }

        if ((settings.SafeLiveContentAnalysis || settings.CaptureHttpBody) && finalBody is not null && finalBody.Length > 0)
        {
            progress.Report(new WebIncidentProgress(sessionId, "Phân tích nội dung trang", 75));
            var bodyText = DecodeBody(finalBody);
            signals = WebContentSignalDetector.Analyze(bodyText, finalUri!);
            AddContentFindings(normalized, finalUri!, finalBody, signals, settings.ExpectedContentSha256, findings);
            manifest.Add(await WriteTextAsync(root, "content-signals.json", "content-signals",
                JsonSerializer.Serialize(signals, JsonOptions), cancellationToken).ConfigureAwait(false));

            progress.Report(new WebIncidentProgress(sessionId, "PhÃ¢n tÃ­ch tÃ i nguyÃªn HTML/JS liÃªn quan", 82));
            liveResources.AddRange(await CollectLinkedResourcesAsync(
                signals,
                finalUri!,
                settings,
                cancellationToken).ConfigureAwait(false));
            if (liveResources.Count > 0)
            {
                manifest.Add(await WriteTextAsync(root, "live-resource-observations.json", "live-resources",
                    JsonSerializer.Serialize(liveResources, JsonOptions), cancellationToken).ConfigureAwait(false));
                manifest.Add(await WriteTextAsync(root, "live-resource-safety.txt", "live-resource-safety",
                    "StorageMode: metadata and hashes only\nReason: linked resources are not written as raw files to avoid preserving potentially malicious payloads.\nEvidenceJson: live-resource-observations.json\n",
                    cancellationToken).ConfigureAwait(false));
                AddLiveResourceFindings(normalized, liveResources, findings);
            }
        }

            if (settings.ProbePlainHttp
                && string.Equals(normalized.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                progress.Report(new WebIncidentProgress(sessionId, "Kiểm tra HTTP không mã hóa", 85));
                var plain = new UriBuilder(normalized)
                {
                    Scheme = Uri.UriSchemeHttp,
                    Port = 80
                }.Uri;
                try
                {
                    var plainResult = await CollectHttpAsync(
                        plain,
                        settings with
                        {
                            MaxBodyBytes = Math.Min(settings.MaxBodyBytes, 64 * 1024),
                            CaptureHttpBody = false,
                            SafeLiveContentAnalysis = false
                        },
                        root,
                        manifest,
                        cancellationToken).ConfigureAwait(false);
                    if (plainResult.Observations.Count > 0)
                    {
                        var first = plainResult.Observations[0];
                        if (first.StatusCode is >= 200 and < 400
                            && string.IsNullOrWhiteSpace(first.RedirectLocation))
                        {
                            findings.Add(Finding.Create(
                                "WEB-HTTP-PLAINTEXT",
                                "Website phản hồi qua HTTP không mã hóa",
                                Severity.Medium,
                                "web-incident.transport",
                                normalized.Host,
                                $"URL: {plain}\nStatus: {first.StatusCode} {first.ReasonPhrase}\nResponseTimeMs: {first.ElapsedMs}",
                                "Ép chuyển hướng HTTP sang HTTPS tại web server/CDN, bật HSTS sau khi xác minh không còn nội dung phụ thuộc HTTP."));
                        }
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
                {
                    _logger.LogDebug(ex, "Plain HTTP probe failed for {Target}", plain);
                }
            }
        }
        else
        {
            progress.Report(new WebIncidentProgress(sessionId, "Bỏ qua live URL probe theo chế độ an toàn với antivirus", 70));
            findings.Add(Finding.Create(
                "WEB-LIVE-PROBE-DISABLED",
                "Không thực hiện kết nối live tới website",
                Severity.Info,
                "web-incident.evidence",
                asset,
                "Chế độ mặc định chỉ phân tích evidence/log/webroot đã có. Không chạy DNS/TLS/HTTP live để giảm nguy cơ Kaspersky PDM chặn ứng dụng.",
                "Nếu cần kiểm tra URL live, bật tùy chọn 'Live URL probe' trong GUI hoặc dùng --web-live-network trong CLI trên máy đã cho phép công cụ chạy."));
        }

        if (!string.IsNullOrWhiteSpace(settings.ServerEvidencePath)
            || !string.IsNullOrWhiteSpace(settings.WebRootPath)
            || !string.IsNullOrWhiteSpace(settings.BaselineManifestPath))
        {
            progress.Report(new WebIncidentProgress(sessionId, "Phân tích log server/webroot/baseline", 90));
            var serverAnalysis = await _serverEvidenceAnalyzer.AnalyzeAsync(
                settings,
                root,
                asset,
                cancellationToken).ConfigureAwait(false);
            serverEvidence = serverAnalysis.Summary;
            manifest.AddRange(serverAnalysis.Manifest);
            findings.AddRange(serverAnalysis.Findings);
        }

        progress.Report(new WebIncidentProgress(sessionId, "Ghi summary", 95));
        var contentShaEvidence = (settings.CaptureHttpBody || settings.SafeLiveContentAnalysis)
            && finalBody is not null
            && finalBody.Length > 0
            ? Sha256Hex(finalBody)
            : "(not captured)";
        findings.Add(Finding.Create(
            "WEB-SNAPSHOT-01",
            "Đã thu thập gói bằng chứng sự cố website",
            Severity.Info,
            "web-incident.evidence",
            asset,
            $"Target: {displayTarget}\nNormalized: {normalizedUrl}\nEvidenceRoot: {root}\nFiles: {manifest.Count}\nCurrentContentSha256: {contentShaEvidence}",
            "Lưu nguyên thư mục evidence, không chỉnh sửa file gốc; dùng manifest SHA256 để bàn giao hoặc đối chiếu sau này."));

        var completed = DateTimeOffset.UtcNow;
        var result = new WebIncidentResult(
            sessionId,
            displayTarget,
            normalizedUrl,
            root,
            started,
            completed,
            dns,
            tls,
            http,
            signals,
            liveResources,
            serverEvidence,
            manifest,
            findings);

        manifest.Add(await WriteTextAsync(root, "summary.json", "summary",
            JsonSerializer.Serialize(result with { Manifest = manifest }, JsonOptions), cancellationToken)
            .ConfigureAwait(false));
        manifest.Add(await WriteTextAsync(root, "manifest.json", "manifest",
            JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken).ConfigureAwait(false));

        progress.Report(new WebIncidentProgress(sessionId, "Hoàn tất", 100));
        return result with { CompletedAt = DateTimeOffset.UtcNow, Manifest = manifest };
    }

    public static Uri NormalizeTarget(string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        var trimmed = target.Trim();
        if (!trimmed.Contains("://", StringComparison.Ordinal))
        {
            trimmed = "https://" + trimmed;
        }
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            || string.IsNullOrWhiteSpace(uri.Host)
            || !(string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                 || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Target phải là domain hoặc URL http/https hợp lệ.", nameof(target));
        }
        return uri;
    }

    private static string PrepareEvidenceRoot(string configuredRoot, string sessionId)
    {
        var baseRoot = string.IsNullOrWhiteSpace(configuredRoot)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecAudit",
                "web-incident")
            : configuredRoot.Trim();
        var root = Path.Combine(baseRoot, sessionId);
        Directory.CreateDirectory(root);
        return root;
    }

    private static async Task<WebDnsObservation> CollectDnsAsync(string host, CancellationToken cancellationToken)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            return new WebDnsObservation(
                host,
                addresses.Select(a => a.ToString()).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
                null);
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return new WebDnsObservation(host, Array.Empty<string>(), ex.Message);
        }
    }

    [SuppressMessage(
        "Security",
        "CA5359:Do not disable certificate validation",
        Justification = "Incident evidence collection must capture invalid certificates and record policy errors instead of aborting.")]
    private static async Task<WebTlsObservation> CollectTlsAsync(
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        SslPolicyErrors policyErrors = SslPolicyErrors.None;
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            await using var stream = tcp.GetStream();
            using var ssl = new SslStream(stream, false, (_, _, _, errors) =>
            {
                policyErrors = errors;
                return true;
            });

            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            }, cancellationToken).ConfigureAwait(false);

            if (ssl.RemoteCertificate is null)
            {
                return new WebTlsObservation(host, port, string.Empty, string.Empty, string.Empty,
                    null, null, policyErrors.ToString(), "Remote certificate is null.");
            }

            using var cert = new X509Certificate2(ssl.RemoteCertificate);
            return new WebTlsObservation(
                host,
                port,
                cert.Subject,
                cert.Issuer,
                cert.Thumbprint ?? string.Empty,
                cert.NotBefore,
                cert.NotAfter,
                policyErrors.ToString(),
                null);
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException)
        {
            return new WebTlsObservation(host, port, string.Empty, string.Empty, string.Empty,
                null, null, policyErrors.ToString(), ex.Message);
        }
    }

    private static async Task<HttpCollectionResult> CollectHttpAsync(
        Uri uri,
        WebIncidentSettings settings,
        string evidenceRoot,
        List<WebIncidentEvidenceFile> manifest,
        CancellationToken cancellationToken)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 3, 120))
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SecAudit-WebIncident", "1.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

        var observations = new List<WebHttpObservation>();
        var current = uri;
        byte[] finalBody = Array.Empty<byte>();
        for (var hop = 0; hop < 6; hop++)
        {
            var shouldReadBody = settings.CaptureHttpBody || settings.SafeLiveContentAnalysis;
            using var request = new HttpRequestMessage(shouldReadBody ? HttpMethod.Get : HttpMethod.Head, current);
            var sw = Stopwatch.StartNew();
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            sw.Stop();

            var body = shouldReadBody
                ? await ReadBoundedAsync(
                    response,
                    Math.Clamp(settings.MaxBodyBytes, 64 * 1024, 25 * 1024 * 1024),
                    cancellationToken).ConfigureAwait(false)
                : Array.Empty<byte>();
            var redirect = response.Headers.Location is null
                ? null
                : new Uri(current, response.Headers.Location).ToString();
            var contentType = response.Content.Headers.ContentType?.ToString() ?? string.Empty;
            var bodyHash = body.Length == 0 ? string.Empty : Sha256Hex(body);
            var observedBytes = shouldReadBody
                ? body.Length
                : response.Content.Headers.ContentLength ?? 0;
            observations.Add(new WebHttpObservation(
                current.ToString(),
                hop,
                (int)response.StatusCode,
                response.ReasonPhrase ?? string.Empty,
                sw.ElapsedMilliseconds,
                redirect,
                contentType,
                observedBytes,
                bodyHash,
                null,
                CaptureHeaders(response)));

            var stem = current.Scheme + "-hop-" + hop.ToString("00", CultureInfo.InvariantCulture);
            manifest.Add(await WriteTextAsync(evidenceRoot, stem + "-headers.txt", "http-headers",
                FormatHeaders(current, response, sw.ElapsedMilliseconds, redirect), cancellationToken)
                .ConfigureAwait(false));
            if (settings.CaptureHttpBody && body.Length > 0)
            {
                manifest.Add(await WriteHttpBodyEvidenceAsync(
                    evidenceRoot,
                    stem,
                    contentType,
                    body,
                    cancellationToken).ConfigureAwait(false));
            }

            finalBody = body;
            if (redirect is null || (int)response.StatusCode is < 300 or > 399)
            {
                return new HttpCollectionResult(observations, finalBody, current);
            }

            current = new Uri(redirect);
        }

        return new HttpCollectionResult(observations, finalBody, current);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (output.Length < maxBytes)
        {
            var remaining = maxBytes - (int)output.Length;
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static void AddTlsFindings(Uri target, WebTlsObservation tls, List<Finding> findings)
    {
        if (tls.Error is not null)
        {
            findings.Add(Finding.Create(
                "WEB-TLS-FAILED",
                "Không thu thập được TLS handshake",
                Severity.Medium,
                "web-incident.transport",
                target.Host,
                $"Host: {tls.Host}:{tls.Port}\nError: {tls.Error}\nPolicyErrors: {tls.PolicyErrors}\nEvidence: tls.txt",
                "Kiểm tra listener HTTPS/CDN/load balancer; nếu dịch vụ đang lỗi, lưu log reverse proxy và trạng thái hạ tầng tại cùng thời điểm."));
            return;
        }

        if (!string.Equals(tls.PolicyErrors, SslPolicyErrors.None.ToString(), StringComparison.Ordinal))
        {
            findings.Add(Finding.Create(
                "WEB-TLS-INVALID",
                "Chứng thư TLS có lỗi xác thực",
                Severity.High,
                "web-incident.transport",
                target.Host,
                $"Subject: {tls.Subject}\nIssuer: {tls.Issuer}\nThumbprint: {tls.Thumbprint}\nPolicyErrors: {tls.PolicyErrors}\nEvidence: tls.txt",
                "Kiểm tra chứng thư có bị thay, hết hạn, sai tên miền hoặc bị proxy trung gian; khôi phục chứng thư hợp lệ và rà soát quyền quản trị CDN/DNS."));
        }

        if (tls.NotAfter.HasValue && tls.NotAfter.Value < DateTimeOffset.UtcNow)
        {
            findings.Add(Finding.Create(
                "WEB-TLS-EXPIRED",
                "Chứng thư TLS đã hết hạn",
                Severity.High,
                "web-incident.transport",
                target.Host,
                $"NotAfter: {tls.NotAfter:O}\nSubject: {tls.Subject}\nThumbprint: {tls.Thumbprint}",
                "Gia hạn/thay chứng thư, kiểm tra pipeline cấp chứng thư tự động và rà soát thay đổi gần nhất trên web server/CDN."));
        }
        else if (tls.NotAfter.HasValue && tls.NotAfter.Value < DateTimeOffset.UtcNow.AddDays(14))
        {
            findings.Add(Finding.Create(
                "WEB-TLS-EXPIRING",
                "Chứng thư TLS sắp hết hạn",
                Severity.Medium,
                "web-incident.transport",
                target.Host,
                $"NotAfter: {tls.NotAfter:O}\nSubject: {tls.Subject}\nThumbprint: {tls.Thumbprint}",
                "Lên lịch gia hạn chứng thư trước khi hết hạn để tránh gián đoạn dịch vụ."));
        }
    }

    private static void AddHttpFindings(
        Uri target,
        IReadOnlyList<WebHttpObservation> observations,
        List<Finding> findings,
        int slowThresholdMs)
    {
        if (observations.Count == 0)
        {
            return;
        }

        var final = observations[^1];
        if (final.Error is not null || final.StatusCode is null)
        {
            findings.Add(Finding.Create(
                "WEB-DOS-UNAVAILABLE",
                "Website không phản hồi HTTP/HTTPS",
                Severity.High,
                "web-incident.availability",
                target.Host,
                $"URL: {final.Url}\nError: {final.Error}\nEvidence: http-observations.json",
                "Xác minh tình trạng web server/CDN/WAF, thu log access/error cùng thời điểm, bật trang bảo trì hoặc chuyển traffic sang hạ tầng dự phòng nếu sự cố còn diễn ra."));
            return;
        }

        if (final.StatusCode >= 500)
        {
            findings.Add(Finding.Create(
                "WEB-DOS-HTTP-5XX",
                "Website trả lỗi máy chủ",
                Severity.High,
                "web-incident.availability",
                target.Host,
                $"URL: {final.Url}\nStatus: {final.StatusCode} {final.ReasonPhrase}\nResponseTimeMs: {final.ElapsedMs}\nEvidence: http-observations.json",
                "Thu log web/app/database trong cùng khung giờ, kiểm tra tải bất thường, lỗi ứng dụng, dung lượng đĩa và trạng thái dịch vụ phía sau reverse proxy."));
        }
        else if (final.StatusCode is 403 or 429)
        {
            findings.Add(Finding.Create(
                "WEB-ACCESS-BLOCKED",
                "Website đang bị chặn hoặc giới hạn truy cập",
                Severity.Medium,
                "web-incident.availability",
                target.Host,
                $"URL: {final.Url}\nStatus: {final.StatusCode} {final.ReasonPhrase}\nResponseTimeMs: {final.ElapsedMs}",
                "Kiểm tra WAF/CDN/rate-limit có đang chặn nhầm người dùng hợp lệ hay đang phản ứng trước lưu lượng tấn công."));
        }

        if (final.ElapsedMs >= Math.Max(1000, slowThresholdMs))
        {
            findings.Add(Finding.Create(
                "WEB-DOS-SLOW",
                "Website phản hồi rất chậm",
                Severity.Medium,
                "web-incident.availability",
                target.Host,
                $"URL: {final.Url}\nResponseTimeMs: {final.ElapsedMs}\nThresholdMs: {slowThresholdMs}",
                "Đối chiếu CPU/RAM/network, log reverse proxy và biểu đồ traffic; nếu đang bị flood, áp dụng rate-limit/WAF/CDN hoặc lọc nguồn tấn công."));
        }

        var firstExternalRedirect = observations
            .Select(o => o.RedirectLocation)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => Uri.TryCreate(x, UriKind.Absolute, out var u) ? u : null)
            .FirstOrDefault(u => u is not null && !string.Equals(u.Host, target.Host, StringComparison.OrdinalIgnoreCase));
        if (firstExternalRedirect is not null)
        {
            findings.Add(Finding.Create(
                "WEB-REDIRECT-EXTERNAL",
                "Website chuyển hướng sang domain khác",
                Severity.Medium,
                "web-incident.content",
                target.Host,
                $"Target: {target}\nRedirect: {firstExternalRedirect}\nEvidence: http-observations.json",
                "Xác minh đây có phải chuyển hướng hợp lệ hay dấu hiệu bị chèn redirect; kiểm tra cấu hình web server, CMS, plugin và file .htaccess/web.config."));
        }
    }

    private static void AddHttpHeaderFindings(
        Uri target,
        IReadOnlyList<WebHttpObservation> observations,
        List<Finding> findings)
    {
        if (observations.Count == 0)
        {
            return;
        }

        var final = observations[^1];
        if (final.StatusCode is null || final.Error is not null)
        {
            return;
        }

        var missing = new List<string>();
        if (string.Equals(target.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !final.Headers.ContainsKey("Strict-Transport-Security"))
        {
            missing.Add("Strict-Transport-Security");
        }
        if (!final.Headers.ContainsKey("Content-Security-Policy"))
        {
            missing.Add("Content-Security-Policy");
        }
        if (!final.Headers.ContainsKey("X-Content-Type-Options"))
        {
            missing.Add("X-Content-Type-Options");
        }
        if (!final.Headers.ContainsKey("Referrer-Policy"))
        {
            missing.Add("Referrer-Policy");
        }

        if (missing.Count > 0)
        {
            findings.Add(Finding.Create(
                "WEB-SECURITY-HEADERS-MISSING",
                "Website thiếu một số header phòng thủ phổ biến",
                Severity.Low,
                "web-incident.hardening",
                target.Host,
                $"URL: {final.Url}\nMissing: {string.Join(", ", missing)}\nEvidence: http-observations.json",
                "Đối chiếu với cấu hình chuẩn của tổ chức; bổ sung HSTS/CSP/X-Content-Type-Options/Referrer-Policy sau khi kiểm thử không làm hỏng ứng dụng."));
        }

        if (TryGetHeader(final.Headers, "Content-Security-Policy", out var csp)
            && (csp.Contains("unsafe-eval", StringComparison.OrdinalIgnoreCase)
                || csp.Contains("unsafe-inline", StringComparison.OrdinalIgnoreCase)
                || csp.Contains('*')))
        {
            findings.Add(Finding.Create(
                "WEB-CSP-WEAK",
                "Content-Security-Policy có cấu hình yếu",
                Severity.Medium,
                "web-incident.hardening",
                target.Host,
                $"URL: {final.Url}\nCSP: {csp}",
                "Siết CSP theo allowlist script/style/frame thật sự cần thiết; loại bỏ unsafe-eval/unsafe-inline nếu ứng dụng cho phép."));
        }

        var leaks = new List<string>();
        if (TryGetHeader(final.Headers, "Server", out var server))
        {
            leaks.Add("Server=" + server);
        }
        if (TryGetHeader(final.Headers, "X-Powered-By", out var poweredBy))
        {
            leaks.Add("X-Powered-By=" + poweredBy);
        }
        if (leaks.Count > 0)
        {
            findings.Add(Finding.Create(
                "WEB-SERVER-FINGERPRINT-LEAK",
                "Website để lộ fingerprint công nghệ qua HTTP header",
                Severity.Info,
                "web-incident.hardening",
                target.Host,
                $"URL: {final.Url}\n{string.Join("\n", leaks)}",
                "Ẩn hoặc rút gọn banner Server/X-Powered-By nếu không cần thiết để giảm thông tin cho attacker khi dò quét."));
        }
    }

    private static void AddContentFindings(
        Uri requested,
        Uri finalUri,
        byte[] body,
        WebContentSignals signals,
        string expectedSha256,
        List<Finding> findings)
    {
        var currentSha = Sha256Hex(body);
        if (!string.IsNullOrWhiteSpace(expectedSha256)
            && !string.Equals(currentSha, expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(Finding.Create(
                "WEB-CONTENT-CHANGED",
                "Nội dung website khác baseline đã biết",
                Severity.High,
                "web-incident.content",
                requested.Host,
                $"URL: {finalUri}\nTitle: {signals.Title ?? "(none)"}\nExpectedSha256: {expectedSha256.Trim()}\nCurrentSha256: {currentSha}\nEvidence: {finalUri.Scheme}-hop-*-body.txt or {finalUri.Scheme}-hop-*-body-metadata.txt",
                "Giữ nguyên bản chụp HTML, so sánh với bản triển khai sạch, kiểm tra tài khoản quản trị CMS/hosting, khôi phục từ backup sạch và xoay vòng mật khẩu/API key."));
        }

        if (signals.RansomOrEncryptionMarker)
        {
            findings.Add(Finding.Create(
                "WEB-RANSOM-MARKER",
                "Nội dung trang có dấu hiệu thông báo mã hóa/đòi tiền chuộc",
                Severity.Critical,
                "web-incident.ransom",
                requested.Host,
                $"URL: {finalUri}\nTitle: {signals.Title ?? "(none)"}\nMatched: {string.Join(", ", signals.MatchedTerms)}\nCurrentSha256: {currentSha}",
                "Cô lập máy chủ origin khỏi Internet, snapshot máy ảo/ổ đĩa trước khi sửa, thu log web/app/database, rà soát webshell/backdoor, khôi phục từ backup sạch và thay toàn bộ bí mật liên quan."));
        }

        if (signals.DefacementMarker)
        {
            findings.Add(Finding.Create(
                "WEB-DEFACE-MARKER",
                "Nội dung trang có dấu hiệu bị thay đổi/deface",
                Severity.High,
                "web-incident.defacement",
                requested.Host,
                $"URL: {finalUri}\nTitle: {signals.Title ?? "(none)"}\nMatched: {string.Join(", ", signals.MatchedTerms)}\nCurrentSha256: {currentSha}",
                "Bật chế độ bảo trì hoặc chuyển sang bản sạch, bảo toàn bản chụp deface, kiểm tra lịch sử deploy/CMS/plugin/tài khoản quản trị và rà soát webshell trước khi đưa website trở lại."));
        }

        if (signals.ExternalRedirectOrFrame)
        {
            findings.Add(Finding.Create(
                "WEB-INJECTED-EXTERNAL",
                "Nội dung trang tham chiếu/chuyển hướng ra domain ngoài",
                Severity.Medium,
                "web-incident.content",
                requested.Host,
                $"URL: {finalUri}\nExternalHosts: {string.Join(", ", signals.ExternalHosts)}\nCurrentSha256: {currentSha}",
                "Đối chiếu các domain ngoài với baseline CDN/analytics hợp lệ; nếu lạ, kiểm tra template/theme/plugin, file JS mới và lịch sử thay đổi nội dung."));
        }

        if (signals.SuspiciousScriptOrObfuscation)
        {
            findings.Add(Finding.Create(
                "WEB-SCRIPT-OBFUSCATION",
                "Nội dung website có dấu hiệu script bị đóng gói/che giấu",
                Severity.Medium,
                "web-incident.content",
                requested.Host,
                $"URL: {finalUri}\nPatterns: {string.Join(", ", signals.SuspiciousPatterns)}\nCurrentSha256: {currentSha}\nEvidence: content-signals.json",
                "So sánh HTML/JS với bản triển khai sạch; nếu pattern xuất hiện trong file mới hoặc template bị sửa, đưa site về maintenance và rà webshell/backdoor trước khi mở lại."));
        }

        if (signals.CredentialOrPaymentPhishingMarker)
        {
            findings.Add(Finding.Create(
                "WEB-PHISHING-MARKER",
                "Nội dung website có dấu hiệu form lừa nhập thông tin nhạy cảm",
                Severity.High,
                "web-incident.content",
                requested.Host,
                $"URL: {finalUri}\nMatched: {string.Join(", ", signals.MatchedTerms)}\nCurrentSha256: {currentSha}\nEvidence: content-signals.json",
                "Kiểm tra template, plugin thanh toán/đăng nhập và JavaScript được chèn; khóa tài khoản quản trị nghi vấn và rà log thay đổi nội dung."));
        }

        if (signals.HiddenIframeOrSkimmerMarker)
        {
            findings.Add(Finding.Create(
                "WEB-HIDDEN-IFRAME-SKIMMER",
                "Nội dung website có dấu hiệu iframe ẩn hoặc skimmer",
                Severity.High,
                "web-incident.content",
                requested.Host,
                $"URL: {finalUri}\nPatterns: {string.Join(", ", signals.SuspiciousPatterns)}\nCurrentSha256: {currentSha}\nEvidence: content-signals.json",
                "Tạm dừng chức năng thanh toán/đăng nhập nếu bị ảnh hưởng; đối chiếu file theme/plugin, xoay vòng khóa API thanh toán và kiểm tra dữ liệu người dùng có bị thu thập trái phép không."));
        }
    }

    private static async Task<IReadOnlyList<WebLiveResourceObservation>> CollectLinkedResourcesAsync(
        WebContentSignals signals,
        Uri finalUri,
        WebIncidentSettings settings,
        CancellationToken cancellationToken)
    {
        var limit = Math.Clamp(settings.MaxLiveLinkedResources, 0, 100);
        if (limit == 0 || signals.LinkedResources.Count == 0)
        {
            return Array.Empty<WebLiveResourceObservation>();
        }

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 3, 60))
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SecAudit-WebIncident", "1.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

        var observations = new List<WebLiveResourceObservation>();
        foreach (var resource in signals.LinkedResources.Take(limit))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Uri.TryCreate(resource.Url, UriKind.Absolute, out var uri))
            {
                continue;
            }

            var externalAllowed = IsAllowedExternalHost(uri.Host, finalUri.Host, settings.AllowedExternalHosts);
            var shouldReadBody = !resource.IsExternal && IsLikelyTextResource(uri, resource.Kind);
            try
            {
                using var request = new HttpRequestMessage(shouldReadBody ? HttpMethod.Get : HttpMethod.Head, uri);
                using var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);

                var contentType = response.Content.Headers.ContentType?.ToString() ?? string.Empty;
                var body = shouldReadBody
                    ? await ReadBoundedAsync(response, Math.Min(settings.MaxBodyBytes, 512 * 1024), cancellationToken)
                        .ConfigureAwait(false)
                    : Array.Empty<byte>();
                var bodyHash = body.Length == 0 ? string.Empty : Sha256Hex(body);
                var resourceSignals = new List<string>();
                if (resource.IsExternal && !externalAllowed)
                {
                    resourceSignals.Add("external-host-not-in-allowlist");
                }
                if (body.Length > 0)
                {
                    resourceSignals.AddRange(WebContentSignalDetector.DetectSuspiciousPatterns(DecodeBody(body)));
                }

                var classification = resourceSignals.Count > 0
                    ? "needs-review"
                    : shouldReadBody
                        ? "text-ok"
                        : resource.IsExternal
                            ? "external-metadata-only"
                            : "metadata-only";
                observations.Add(new WebLiveResourceObservation(
                    resource.Url,
                    resource.Kind,
                    resource.IsExternal,
                    (int)response.StatusCode,
                    contentType,
                    shouldReadBody ? body.Length : response.Content.Headers.ContentLength ?? 0,
                    bodyHash,
                    classification,
                    resourceSignals.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                    null));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
            {
                observations.Add(new WebLiveResourceObservation(
                    resource.Url,
                    resource.Kind,
                    resource.IsExternal,
                    null,
                    string.Empty,
                    0,
                    string.Empty,
                    "error",
                    Array.Empty<string>(),
                    ex.Message));
            }
        }

        return observations;
    }

    private static void AddLiveResourceFindings(
        Uri target,
        IReadOnlyList<WebLiveResourceObservation> resources,
        List<Finding> findings)
    {
        var unallowedExternal = resources
            .Where(r => r.IsExternal
                && r.Signals.Contains("external-host-not-in-allowlist", StringComparer.OrdinalIgnoreCase)
                && r.Kind is "script" or "iframe" or "form")
            .Take(20)
            .ToArray();
        if (unallowedExternal.Length > 0)
        {
            findings.Add(Finding.Create(
                "WEB-EXTERNAL-ACTIVE-CONTENT",
                "Website tham chiếu script/iframe/form ngoài allowlist",
                Severity.Medium,
                "web-incident.content",
                target.Host,
                "Resources:\n" + string.Join("\n", unallowedExternal.Select(r => $"{r.Kind}: {r.Url}")) + "\nEvidence: live-resource-observations.json",
                "Đối chiếu với danh sách CDN/analytics/payment hợp lệ của tổ chức. Nếu domain lạ mới xuất hiện, kiểm tra template/plugin và lịch sử deploy."));
        }

        var suspiciousSameOrigin = resources
            .Where(r => !r.IsExternal && r.Signals.Count > 0)
            .Take(20)
            .ToArray();
        if (suspiciousSameOrigin.Length > 0)
        {
            findings.Add(Finding.Create(
                "WEB-LIVE-RESOURCE-SUSPICIOUS",
                "Tài nguyên HTML/JS cùng website có dấu hiệu đáng ngờ",
                Severity.High,
                "web-incident.content",
                target.Host,
                "Resources:\n" + string.Join("\n", suspiciousSameOrigin.Select(r => $"{r.Kind}: {r.Url} [{string.Join(", ", r.Signals)}]")) + "\nEvidence: live-resource-observations.json",
                "Tải bản sạch từ repository/backup để so sánh hash, rà file JS/template mới sửa và kiểm tra khả năng bị chèn mã độc hoặc webshell sinh nội dung động."));
        }
    }

    private static bool IsAllowedExternalHost(
        string host,
        string targetHost,
        IReadOnlyList<string> allowedHosts)
    {
        if (string.Equals(host, targetHost, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        foreach (var allowed in allowedHosts.Where(h => !string.IsNullOrWhiteSpace(h)))
        {
            var normalized = allowed.Trim().TrimStart('*').TrimStart('.');
            if (string.Equals(host, normalized, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + normalized, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLikelyTextResource(Uri uri, string kind)
    {
        if (kind is "script" or "link" or "iframe" or "form")
        {
            var path = uri.AbsolutePath;
            return path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".css", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".html", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".htm", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                || !Path.HasExtension(path);
        }

        return false;
    }

    private static bool TryGetHeader(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        string name,
        out string value)
    {
        if (headers.TryGetValue(name, out var values) && values.Count > 0)
        {
            value = string.Join(", ", values);
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static async Task<WebIncidentEvidenceFile> WriteTextAsync(
        string root,
        string name,
        string kind,
        string content,
        CancellationToken cancellationToken)
        => await WriteBytesAsync(root, name, kind, Encoding.UTF8.GetBytes(content), cancellationToken)
            .ConfigureAwait(false);

    private static async Task<WebIncidentEvidenceFile> WriteBytesAsync(
        string root,
        string name,
        string kind,
        byte[] content,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(root, name);
        await File.WriteAllBytesAsync(path, content, cancellationToken).ConfigureAwait(false);
        return new WebIncidentEvidenceFile(
            name,
            path,
            kind,
            content.LongLength,
            Sha256Hex(content),
            DateTimeOffset.UtcNow);
    }

    private static async Task<WebIncidentEvidenceFile> WriteHttpBodyEvidenceAsync(
        string root,
        string stem,
        string contentType,
        byte[] body,
        CancellationToken cancellationToken)
    {
        var bodySha256 = Sha256Hex(body);
        if (IsTextualHttpBody(contentType, body))
        {
            var text = DecodeBody(body);
            var content = new StringBuilder()
                .AppendLine("Content-Type: " + EmptyAsUnknown(contentType))
                .AppendLine("Body-SHA256: " + bodySha256)
                .AppendLine("CapturedBytes: " + body.LongLength.ToString(CultureInfo.InvariantCulture))
                .AppendLine("StorageMode: text snapshot")
                .AppendLine()
                .Append(text)
                .ToString();
            return await WriteTextAsync(root, stem + "-body.txt", "http-body-text", content, cancellationToken)
                .ConfigureAwait(false);
        }

        var metadata = new StringBuilder()
            .AppendLine("Content-Type: " + EmptyAsUnknown(contentType))
            .AppendLine("Body-SHA256: " + bodySha256)
            .AppendLine("CapturedBytes: " + body.LongLength.ToString(CultureInfo.InvariantCulture))
            .AppendLine("StorageMode: metadata only")
            .AppendLine("Reason: non-text HTTP body is not written to disk to avoid preserving executable/download payloads during incident triage.")
            .AppendLine("HexPreviewFirst256Bytes: " + HexPreview(body, 256))
            .ToString();
        return await WriteTextAsync(root, stem + "-body-metadata.txt", "http-body-metadata", metadata, cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool IsTextualHttpBody(string contentType, byte[] body)
    {
        var lower = contentType.ToLowerInvariant();
        if (lower.StartsWith("text/", StringComparison.Ordinal)
            || lower.Contains("json", StringComparison.Ordinal)
            || lower.Contains("xml", StringComparison.Ordinal)
            || lower.Contains("javascript", StringComparison.Ordinal)
            || lower.Contains("ecmascript", StringComparison.Ordinal)
            || lower.Contains("x-www-form-urlencoded", StringComparison.Ordinal))
        {
            return true;
        }

        return LooksLikeUtf8Text(body);
    }

    private static bool LooksLikeUtf8Text(byte[] body)
    {
        if (body.Length == 0)
        {
            return true;
        }
        var sampleLength = Math.Min(body.Length, 4096);
        var control = 0;
        var printable = 0;
        for (var i = 0; i < sampleLength; i++)
        {
            var b = body[i];
            if (b == 0)
            {
                return false;
            }
            if (b is >= 0x20 and <= 0x7E || b is 0x09 or 0x0A or 0x0D || b >= 0x80)
            {
                printable++;
            }
            else
            {
                control++;
            }
        }

        return printable >= sampleLength * 0.90 && control <= sampleLength * 0.02;
    }

    private static string HexPreview(byte[] body, int maxBytes)
        => Convert.ToHexString(body.AsSpan(0, Math.Min(body.Length, maxBytes)).ToArray());

    private static string EmptyAsUnknown(string value)
        => string.IsNullOrWhiteSpace(value) ? "(unknown)" : value.Trim();

    private static string Sha256Hex(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes));

    private static string DecodeBody(byte[] body)
    {
        try
        {
            return Encoding.UTF8.GetString(body);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(body);
        }
    }

    private static string FormatDns(WebDnsObservation dns)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Host: " + dns.Host);
        if (dns.Error is not null)
        {
            sb.AppendLine("Error: " + dns.Error);
            return sb.ToString();
        }
        foreach (var address in dns.Addresses)
        {
            sb.AppendLine("Address: " + address);
        }
        return sb.ToString();
    }

    private static string FormatTls(WebTlsObservation tls)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Host: " + tls.Host + ":" + tls.Port.ToString(CultureInfo.InvariantCulture));
        sb.AppendLine("PolicyErrors: " + tls.PolicyErrors);
        if (tls.Error is not null)
        {
            sb.AppendLine("Error: " + tls.Error);
            return sb.ToString();
        }
        sb.AppendLine("Subject: " + tls.Subject);
        sb.AppendLine("Issuer: " + tls.Issuer);
        sb.AppendLine("Thumbprint: " + tls.Thumbprint);
        sb.AppendLine("NotBefore: " + tls.NotBefore?.ToString("O", CultureInfo.InvariantCulture));
        sb.AppendLine("NotAfter: " + tls.NotAfter?.ToString("O", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static Dictionary<string, IReadOnlyList<string>> CaptureHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
        {
            headers[header.Key] = header.Value.ToArray();
        }
        foreach (var header in response.Content.Headers)
        {
            headers[header.Key] = header.Value.ToArray();
        }
        return headers;
    }

    private static Dictionary<string, IReadOnlyList<string>> EmptyHeaders()
        => new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

    private static string FormatHeaders(
        Uri uri,
        HttpResponseMessage response,
        long elapsedMs,
        string? redirect)
    {
        var sb = new StringBuilder();
        sb.AppendLine("URL: " + uri);
        sb.AppendLine("Status: " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture)
            + " " + response.ReasonPhrase);
        sb.AppendLine("ElapsedMs: " + elapsedMs.ToString(CultureInfo.InvariantCulture));
        if (redirect is not null)
        {
            sb.AppendLine("RedirectLocation: " + redirect);
        }
        sb.AppendLine();
        sb.AppendLine("[Response headers]");
        foreach (var header in response.Headers.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine(header.Key + ": " + string.Join(", ", header.Value));
        }
        foreach (var header in response.Content.Headers.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine(header.Key + ": " + string.Join(", ", header.Value));
        }
        return sb.ToString();
    }

    private static string BuildPlaybook(string target, bool liveProbe)
        => $"""
           # Web incident response playbook

           Target: {target}
           Live URL probe: {(liveProbe ? "enabled" : "disabled (evidence-only mode)")}

           1. Preserve evidence first: keep this folder unchanged and copy it read-only.
           2. If the site is still defaced, unavailable, or showing ransom content, route traffic to maintenance/CDN/WAF protection before editing files.
           3. Collect server-side evidence: web access log, error log, application log, deployment history, CMS/plugin audit log, database log, firewall/CDN/WAF log.
           4. Compare current content SHA256 with the last clean deployment artifact or backup.
           5. Hunt for webshell/backdoor, new admin accounts, unknown cron/task/service, changed .htaccess/web.config, injected JavaScript and modified templates.
           6. Rotate secrets: hosting panel, CMS admin, database password, SSH/RDP/VPN account, API keys, CDN/DNS account.
           7. Restore from a known-clean backup or redeploy clean artifact; patch CMS/core/plugin/framework before reopening public traffic.
           8. Keep chain-of-custody: record who collected evidence, time, source IP, target URL, and SHA256 manifest.
           """;

    private static string SafeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.Select(c => invalid.Contains(c) ? '_' : c).ToArray();
        return new string(chars).Trim('_');
    }

    private sealed record HttpCollectionResult(
        IReadOnlyList<WebHttpObservation> Observations,
        byte[] FinalBody,
        Uri FinalUri);
}
