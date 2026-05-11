using FluentAssertions;
using SecAudit.Modules.LogForensics.LinuxIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class LinuxIncidentReportBuilderTests
{
    private static LinuxIncidentReportBuilder.ReportContext BuildSampleContext()
    {
        var root = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "secaudit-rb-" + Guid.NewGuid().ToString("N")[..10]);
        System.IO.Directory.CreateDirectory(root);
        try
        {
            var auth = new System.Text.StringBuilder();
            for (var i = 0; i < 30; i++)
            {
                auth.AppendLine($"Mar 14 10:{i:D2}:00 host sshd[1]: Failed password for victim from 89.187.163.211 port 22");
            }
            auth.AppendLine("Mar 10 08:00:00 host sshd[2]: Accepted publickey for victim from 10.0.2.10 port 22 ssh2");
            auth.AppendLine("Mar 14 23:45:17 host sshd[3]: Accepted password for victim from 89.187.163.211 port 22 ssh2");
            System.IO.Directory.CreateDirectory(System.IO.Path.Combine(root, "var", "log"));
            System.IO.File.WriteAllText(System.IO.Path.Combine(root, "var", "log", "auth.log"), auth.ToString());
            System.IO.Directory.CreateDirectory(System.IO.Path.Combine(root, "etc", "sudoers.d"));
            System.IO.File.WriteAllText(System.IO.Path.Combine(root, "etc", "sudoers.d", "victim"),
                "victim ALL=(ALL) NOPASSWD:ALL\n");
            System.IO.Directory.CreateDirectory(System.IO.Path.Combine(root, "var", "spool", "cron", "crontabs"));
            System.IO.File.WriteAllText(System.IO.Path.Combine(root, "var", "spool", "cron", "crontabs", "victim"),
                "@reboot /usr/local/bin/.crond --beacon\n");
            System.IO.Directory.CreateDirectory(System.IO.Path.Combine(root, "home", "victim", "Documents"));
            System.IO.File.WriteAllText(
                System.IO.Path.Combine(root, "home", "victim", "Documents", "README_LOCKED.txt"),
                "Tất cả tập tin của bạn đã bị mã hóa.\nThanh toán 0.5 BTC tới bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\nEmail: phantom_support@protonmail.com\n");
            System.IO.File.WriteAllText(
                System.IO.Path.Combine(root, "home", "victim", "Documents", "Cong_van_bi_mat.pdf.locked"),
                "binary-payload");

            var ar = new LinuxIncidentAnalyzer().Analyze(root, "DAVE", CancellationToken.None);
            return new LinuxIncidentReportBuilder.ReportContext("DAVE", root, DateTimeOffset.Parse("2026-05-10T01:00:00+07:00"), ar);
        }
        finally
        {
            // We keep the temp dir alive for the test method only — caller should
            // clean up via a separate teardown. For these read-only assertions we
            // can leave it; the OS reaps temp eventually.
        }
    }

    [Fact]
    public void Markdown_contains_all_six_sections()
    {
        var ctx = BuildSampleContext();
        var md = LinuxIncidentReportBuilder.BuildMarkdown(ctx);

        md.Should().Contain("# Báo cáo điều tra sự cố");
        md.Should().Contain("## 1. Dòng thời gian");
        md.Should().Contain("## 2. Đánh giá leo thang đặc quyền");
        md.Should().Contain("## 3. Payload & cấu hình mã hoá");
        md.Should().Contain("## 4. Persistence");
        md.Should().Contain("## 5. IOC tóm tắt");
        md.Should().Contain("## 6. Khuyến nghị xử lý");
    }

    [Fact]
    public void Markdown_categorises_iocs_into_typed_table_rows()
    {
        var ctx = BuildSampleContext();
        var md = LinuxIncidentReportBuilder.BuildMarkdown(ctx);

        md.Should().Contain("| IP nguồn / C2 | `89.187.163.211` |");
        md.Should().Contain("phantom_support@protonmail.com");
        md.Should().Contain("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    }

    [Fact]
    public void Markdown_renders_ssh_finding_evidence_in_fenced_block()
    {
        var ctx = BuildSampleContext();
        var md = LinuxIncidentReportBuilder.BuildMarkdown(ctx);

        md.Should().Contain("```");
        md.Should().Contain("89.187.163.211");
        md.Should().Contain("**MITRE ATT&CK:**");
    }

    [Fact]
    public void Html_renders_complete_document_with_styling()
    {
        var ctx = BuildSampleContext();
        var html = LinuxIncidentReportBuilder.BuildHtml(ctx);

        html.Should().StartWith("<!doctype html>");
        html.Should().Contain("<title>SecAudit");
        html.Should().Contain("<h1>");
        html.Should().Contain("<h2>");
        html.Should().Contain("<table>");
        html.Should().Contain("<strong>");
        html.Should().Contain("</body></html>");
    }

    [Fact]
    public void Html_escapes_and_does_not_emit_raw_markdown()
    {
        var ctx = BuildSampleContext();
        var html = LinuxIncidentReportBuilder.BuildHtml(ctx);

        // The fenced ```...``` markers must be converted to <pre>, not left raw.
        html.Should().NotContain("```");
        // Inline `code` markers must become <code>.
        html.Should().NotContain("`89.187.163.211`");
    }

    [Fact]
    public void Empty_result_still_produces_valid_skeleton()
    {
        var emptyAr = new LinuxIncidentAnalyzer.AnalysisResult(
            Array.Empty<SecAudit.Core.Models.Finding>(),
            FilesScanned: 0,
            ExtractedIocs: Array.Empty<string>(),
            ExtractedOciTempDir: null);
        var ctx = new LinuxIncidentReportBuilder.ReportContext(
            "DAVE", "/dev/null", DateTimeOffset.UtcNow, emptyAr);

        var md = LinuxIncidentReportBuilder.BuildMarkdown(ctx);
        md.Should().Contain("Không phát hiện sự kiện SSH");
        md.Should().Contain("Không phát hiện cấu hình sudoers");
        md.Should().Contain("Không phát hiện ransom note");
        md.Should().Contain("Không phát hiện cron persistence");
    }
}
