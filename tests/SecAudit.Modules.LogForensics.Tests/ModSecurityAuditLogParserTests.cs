using FluentAssertions;
using SecAudit.Modules.LogForensics.WebIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Locks down ModSecurity serial-format audit-log parsing. Builds canonical samples
/// at runtime from harmless fragments so the test DLL ships clean.
/// </summary>
public sealed class ModSecurityAuditLogParserTests
{
    [Fact]
    public void LooksLikeAuditLog_recognises_serial_boundary()
    {
        var sample = "--abcdef-A--\nfoo bar\n--abcdef-Z--\n";
        ModSecurityAuditLogParser.LooksLikeAuditLog(sample).Should().BeTrue();
    }

    [Fact]
    public void LooksLikeAuditLog_returns_false_for_apache_combined()
    {
        var apache = "127.0.0.1 - - [01/May/2026:10:00:00 +0700] \"GET / HTTP/1.1\" 200 1024 \"-\" \"curl/8.0\"";
        ModSecurityAuditLogParser.LooksLikeAuditLog(apache).Should().BeFalse();
    }

    [Fact]
    public void Parse_extracts_method_path_status_rule_from_full_transaction()
    {
        var tx = string.Join('\n',
            "--Z9zU-A--",
            "[01/May/2026:10:15:42 +0700] Z9zUaQ 203.0.113.7 5343 10.0.0.1 80",
            "--Z9zU-B--",
            "GET /admin/login HTTP/1.1",
            "Host: example.test",
            "User-Agent: testclient/1.0",
            "",
            "--Z9zU-F--",
            "HTTP/1.1 403 Forbidden",
            "Content-Length: 0",
            "",
            "--Z9zU-H--",
            "Message: Access denied with code 403 (phase 2). [id \"942100\"] [msg \"sql probe blocked\"] [severity \"CRITICAL\"]",
            "",
            "--Z9zU-Z--",
            "");

        var events = ModSecurityAuditLogParser.Parse(tx, "audit.log");
        events.Should().HaveCount(1);

        var e = events[0];
        e.Method.Should().Be("GET");
        e.Path.Should().Be("/admin/login");
        e.SourceIp.Should().Be("203.0.113.7");
        e.StatusCode.Should().Be(403);
        e.Rule.Should().Be("ModSecurity:942100");
        e.UserAgent.Should().Be("testclient/1.0");
        e.SourceFile.Should().Be("audit.log");
    }

    [Fact]
    public void Parse_returns_empty_when_no_messages()
    {
        var tx = string.Join('\n',
            "--AA-A--",
            "[01/May/2026:10:15:42 +0700] AA 1.2.3.4 80 5.6.7.8 443",
            "--AA-B--",
            "GET / HTTP/1.1",
            "",
            "--AA-Z--",
            "");

        ModSecurityAuditLogParser.Parse(tx, "audit.log").Should().BeEmpty();
    }

    [Fact]
    public void Parse_handles_multiple_transactions_in_one_file()
    {
        var tx1 = string.Join('\n',
            "--T1-A--",
            "[01/May/2026:10:00:00 +0000] T1 10.0.0.1 1 10.0.0.2 80",
            "--T1-B--",
            "POST /api HTTP/1.1",
            "",
            "--T1-F--",
            "HTTP/1.1 403 Forbidden",
            "",
            "--T1-H--",
            "Message: blocked. [id \"100\"] [msg \"rule one\"]",
            "",
            "--T1-Z--",
            "");
        var tx2 = string.Join('\n',
            "--T2-A--",
            "[01/May/2026:10:00:01 +0000] T2 10.0.0.3 2 10.0.0.2 80",
            "--T2-B--",
            "GET /b HTTP/1.1",
            "",
            "--T2-F--",
            "HTTP/1.1 403 Forbidden",
            "",
            "--T2-H--",
            "Message: blocked. [id \"200\"] [msg \"rule two\"]",
            "",
            "--T2-Z--",
            "");
        var combined = tx1 + "\n" + tx2;

        var events = ModSecurityAuditLogParser.Parse(combined, "audit.log");
        events.Should().HaveCount(2);
        events[0].Rule.Should().Be("ModSecurity:100");
        events[1].Rule.Should().Be("ModSecurity:200");
    }

    [Fact]
    public void Parse_returns_empty_for_non_audit_input()
    {
        ModSecurityAuditLogParser.Parse("hello world", "x").Should().BeEmpty();
        ModSecurityAuditLogParser.Parse(string.Empty, "x").Should().BeEmpty();
    }
}
