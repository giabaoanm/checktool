using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.LinuxIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// End-to-end tests on a synthetic Linux rootfs built per-test in a temp dir.
/// Verifies each detector independently and that an empty rootfs yields zero
/// findings (so callers must rely on the module-level "empty scan" sanity rule).
/// </summary>
public sealed class LinuxIncidentAnalyzerTests : IDisposable
{
    private readonly string _root;
    private readonly LinuxIncidentAnalyzer _sut = new();

    public LinuxIncidentAnalyzerTests()
    {
        _root = Path.Combine(Path.GetTempPath(),
            "secaudit-test-rootfs-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    private void WriteFile(string relPath, string content)
    {
        var full = Path.Combine(_root, relPath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content);
    }

    [Fact]
    public void Detects_SSH_brute_force()
    {
        var lines = new System.Text.StringBuilder();
        for (var i = 0; i < 150; i++)
        {
            lines.AppendLine($"Mar 14 10:{(i % 60):D2}:00 host sshd[1234]: Failed password for victim from 89.187.163.211 port {1024 + i} ssh2");
        }
        WriteFile("var/log/auth.log", lines.ToString());

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f => f.Id == "LIN-SSH-BF" && f.Severity == Severity.High);
        r.Findings.Should().Contain(f => f.AttackTechniqueIds.Contains("T1110"));
    }

    [Fact]
    public void Detects_suspicious_password_login_after_brute_force()
    {
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < 20; i++)
        {
            sb.AppendLine($"Mar 14 10:{i:D2}:00 host sshd[1234]: Failed password for victim from 89.187.163.211 port 22");
        }
        sb.AppendLine("Mar 14 23:45:17 host sshd[9999]: Accepted password for victim from 89.187.163.211 port 22 ssh2");
        WriteFile("var/log/auth.log", sb.ToString());

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f => f.Id.StartsWith("LIN-SSH-ACCEPTED-")
            && f.Severity == Severity.Critical
            && f.Evidence.Contains("89.187.163.211"));
    }

    [Fact]
    public void Detects_password_login_when_user_normally_uses_publickey()
    {
        var auth = "Mar 10 08:00:00 host sshd[1]: Accepted publickey for victim from 10.0.2.10 port 22 ssh2\n"
                 + "Mar 14 23:45:17 host sshd[2]: Accepted password for victim from 89.187.163.211 port 22 ssh2\n";
        WriteFile("var/log/auth.log", auth);

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f => f.Id.StartsWith("LIN-SSH-ACCEPTED-89-"));
    }

    [Fact]
    public void Detects_NOPASSWD_ALL_in_sudoers_d()
    {
        WriteFile("etc/sudoers.d/victim", "victim ALL=(ALL) NOPASSWD:ALL\n");

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f =>
            f.Id.StartsWith("LIN-SUDOERS-NOPASSWD-")
            && f.Severity == Severity.High
            && f.Evidence.Contains("NOPASSWD"));
    }

    [Fact]
    public void Detects_cron_persistence_with_hidden_binary_and_at_reboot()
    {
        WriteFile("var/spool/cron/crontabs/victim",
            "@reboot /usr/local/bin/.crond --beacon >/dev/null 2>&1\n"
            + "0 3 * * * /usr/local/bin/.crond --cleanup 2>/dev/null\n");

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f =>
            f.Id.StartsWith("LIN-CRON-PERSISTENCE-")
            && f.Severity == Severity.High);
    }

    [Fact]
    public void Detects_ransom_note_in_user_home()
    {
        WriteFile("home/victim/Documents/README_LOCKED.txt",
            "Tất cả tập tin của bạn đã bị mã hóa.\n"
            + "Hãy thanh toán 0.5 BTC tới bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh.\n"
            + "Liên hệ: phantom_support@protonmail.com\n");

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f =>
            f.Id.StartsWith("LIN-RANSOM-NOTE-")
            && f.Severity == Severity.Critical
            && f.AttackTechniqueIds.Contains("T1486"));
        r.ExtractedIocs.Should().Contain(i => i.Contains("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"));
        r.ExtractedIocs.Should().Contain(i => i.Contains("phantom_support@protonmail.com"));
    }

    [Fact]
    public void Detects_locked_extension_burst()
    {
        for (var i = 0; i < 6; i++)
        {
            WriteFile($"home/victim/Documents/file{i}.pdf.locked", "ENCRYPTED");
        }

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().Contain(f =>
            f.Id == "LIN-ENCRYPTED-EXT-locked"
            && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Extracts_public_IP_email_BTC_from_artifacts()
    {
        WriteFile("opt/.phantom/.config.json",
            "{\"c2\": \"http://89.187.163.211:8443/api/v1/keys\", "
            + "\"contact\": \"phantom_support@protonmail.com\", "
            + "\"btc\": \"bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\"}");

        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.ExtractedIocs.Should().Contain(i => i == "ip:89.187.163.211");
        r.ExtractedIocs.Should().Contain(i => i.StartsWith("url:http://89.187.163.211"));
        r.ExtractedIocs.Should().Contain(i => i == "email:phantom_support@protonmail.com");
        r.ExtractedIocs.Should().Contain(i => i.Contains("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"));
    }

    [Fact]
    public void Skips_RFC1918_internal_IPs_from_IOC_list()
    {
        WriteFile("opt/x.txt", "internal IP 10.0.2.10 and 192.168.1.1 should be skipped");
        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.ExtractedIocs.Should().NotContain(i => i == "ip:10.0.2.10" || i == "ip:192.168.1.1");
    }

    [Fact]
    public void Empty_rootfs_yields_zero_findings_and_zero_scanned()
    {
        var r = _sut.Analyze(_root, "TEST", CancellationToken.None);

        r.Findings.Should().BeEmpty();
        r.FilesScanned.Should().Be(0);
    }

    [Fact]
    public void End_to_end_synthetic_CryptoPhantom_scenario()
    {
        // Mirrors the real victim image we analysed: brute-force followed by password
        // login, NOPASSWD sudoers, cron persistence, encrypted file + ransom note.
        var auth = new System.Text.StringBuilder();
        for (var i = 0; i < 30; i++)
        {
            auth.AppendLine($"Mar 14 10:{i:D2}:00 host sshd[1]: Failed password for victim from 89.187.163.211 port 22");
        }
        auth.AppendLine("Mar 10 08:00:00 host sshd[2]: Accepted publickey for victim from 10.0.2.10 port 22 ssh2");
        auth.AppendLine("Mar 14 23:45:17 host sshd[3]: Accepted password for victim from 89.187.163.211 port 22 ssh2");
        WriteFile("var/log/auth.log", auth.ToString());
        WriteFile("etc/sudoers.d/victim", "victim ALL=(ALL) NOPASSWD:ALL\n");
        WriteFile("var/spool/cron/crontabs/victim",
            "@reboot /usr/local/bin/.crond --beacon\n");
        WriteFile("home/victim/Documents/README_LOCKED.txt",
            "Tất cả tập tin của bạn đã bị mã hóa.\nThanh toán 0.5 BTC tới bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
            + "Email: phantom_support@protonmail.com\n");
        WriteFile("home/victim/Documents/Cong_van_bi_mat.pdf.locked", "binary-payload");

        var r = _sut.Analyze(_root, "DAVE", CancellationToken.None);

        r.Findings.Should().HaveCountGreaterThanOrEqualTo(5);
        r.Findings.Should().Contain(f => f.Id.StartsWith("LIN-SSH-ACCEPTED-89-"));
        r.Findings.Should().Contain(f => f.Id.StartsWith("LIN-SUDOERS-NOPASSWD-"));
        r.Findings.Should().Contain(f => f.Id.StartsWith("LIN-CRON-PERSISTENCE-"));
        r.Findings.Should().Contain(f => f.Id.StartsWith("LIN-RANSOM-NOTE-"));
        r.Findings.Should().Contain(f => f.Id == "LIN-ENCRYPTED-EXT-locked");
        r.Findings.Should().Contain(f => f.Id == "LIN-IOC-SUMMARY");
        r.ExtractedIocs.Should().Contain(i => i.Contains("89.187.163.211"));
        r.ExtractedIocs.Should().Contain(i => i.Contains("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"));
    }
}
