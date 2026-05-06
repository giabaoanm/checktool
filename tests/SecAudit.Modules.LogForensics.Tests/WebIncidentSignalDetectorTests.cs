using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SecAudit.Modules.LogForensics.WebIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class WebIncidentSignalDetectorTests
{
    [Fact]
    public void Analyze_detects_defacement_and_title()
    {
        var html = """
            <html>
              <head><title>Official site</title></head>
              <body>Hacked by test team</body>
            </html>
            """;

        var signals = WebContentSignalDetector.Analyze(html, new Uri("https://example.gov.vn/"));

        signals.Title.Should().Be("Official site");
        signals.DefacementMarker.Should().BeTrue();
        signals.RansomOrEncryptionMarker.Should().BeFalse();
        signals.MatchedTerms.Should().Contain("hacked by");
    }

    [Fact]
    public void Analyze_detects_ransom_message()
    {
        var html = """
            <html>
              <body>Your files are encrypted. Pay bitcoin to recover.</body>
            </html>
            """;

        var signals = WebContentSignalDetector.Analyze(html, new Uri("https://example.gov.vn/"));

        signals.RansomOrEncryptionMarker.Should().BeTrue();
        signals.MatchedTerms.Should().Contain("your files are encrypted");
        signals.MatchedTerms.Should().Contain("bitcoin");
    }

    [Fact]
    public void Analyze_extracts_external_script_and_meta_refresh_hosts()
    {
        var html = """
            <html>
              <head><meta http-equiv="refresh" content="0;url=https://evil.example/login"></head>
              <body><script src="https://cdn.example.net/a.js"></script></body>
            </html>
            """;

        var signals = WebContentSignalDetector.Analyze(html, new Uri("https://example.gov.vn/"));

        signals.ExternalRedirectOrFrame.Should().BeTrue();
        signals.ExternalHosts.Should().Contain(new[] { "cdn.example.net", "evil.example" });
    }

    [Fact]
    public void Analyze_detects_obfuscated_script_hidden_iframe_and_linked_resources()
    {
        var html = """
            <html>
              <body>
                <script src="/assets/app.js"></script>
                <script src="https://cdn.bad.example/p.js"></script>
                <iframe src="https://frame.bad.example/pay" style="display:none"></iframe>
                <script>var s = String.fromCharCode(65,66,67);</script>
              </body>
            </html>
            """;

        var signals = WebContentSignalDetector.Analyze(html, new Uri("https://example.gov.vn/"));

        signals.SuspiciousScriptOrObfuscation.Should().BeTrue();
        signals.HiddenIframeOrSkimmerMarker.Should().BeTrue();
        signals.SuspiciousPatterns.Should().Contain("String.fromCharCode");
        signals.LinkedResources.Should().Contain(r => r.Kind == "script" && !r.IsExternal && r.Url == "https://example.gov.vn/assets/app.js");
        signals.LinkedResources.Should().Contain(r => r.Kind == "script" && r.IsExternal && r.Url == "https://cdn.bad.example/p.js");
        signals.LinkedResources.Should().Contain(r => r.Kind == "iframe" && r.IsExternal && r.Url == "https://frame.bad.example/pay");
    }

    [Fact]
    public void Analyze_detects_credential_or_payment_phishing_marker()
    {
        var html = """
            <html>
              <body>Session expired. Please verify your account and confirm your password.</body>
            </html>
            """;

        var signals = WebContentSignalDetector.Analyze(html, new Uri("https://example.gov.vn/"));

        signals.CredentialOrPaymentPhishingMarker.Should().BeTrue();
        signals.MatchedTerms.Should().Contain("verify your account");
        signals.MatchedTerms.Should().Contain("confirm your password");
    }

    [Fact]
    public void NormalizeTarget_defaults_to_https()
    {
        var uri = WebIncidentEvidenceCollector.NormalizeTarget("example.gov.vn/path");

        uri.Scheme.Should().Be("https");
        uri.Host.Should().Be("example.gov.vn");
        uri.AbsolutePath.Should().Be("/path");
    }

    [Fact]
    public async Task CollectAsync_allows_evidence_only_without_live_url()
    {
        var root = Path.Combine(Path.GetTempPath(), "SecAudit.WebIncidentEvidenceOnlyTests", Guid.NewGuid().ToString("N"));
        var evidence = Path.Combine(root, "evidence");
        var webroot = Path.Combine(root, "webroot");
        Directory.CreateDirectory(webroot);
        await File.WriteAllTextAsync(Path.Combine(webroot, "index.html"), "<html><title>Clean</title></html>");

        var settings = new WebIncidentSettings
        {
            EvidenceRoot = evidence,
            WebRootPath = webroot
        };
        var collector = new WebIncidentEvidenceCollector(
            new WebServerEvidenceAnalyzer(),
            NullLogger<WebIncidentEvidenceCollector>.Instance);

        var result = await collector.CollectAsync(
            string.Empty,
            settings,
            new Progress<WebIncidentProgress>(),
            CancellationToken.None);

        result.NormalizedUrl.Should().Be("(evidence-only)");
        result.Dns.Should().BeNull();
        result.Http.Should().BeEmpty();
        result.Findings.Select(f => f.Id).Should().Contain("WEB-LIVE-PROBE-DISABLED");
        result.Manifest.Select(m => m.Name).Should().Contain("webroot-manifest.csv");
    }
}
